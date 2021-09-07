/****************************************************************************
 * Driver for Solarflare network controllers and boards
 * Copyright 2008-2017 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include "net_driver.h"
#include "nic.h"
#include "efx_common.h"
#include "efx_devlink.h"
#include "io.h"
#include "mcdi_pcol.h"
#include "aoe.h"

struct efx_mcdi_copy_buffer {
	_MCDI_DECLARE_BUF(buffer, MCDI_CTL_SDU_LEN_MAX);
};

/**************************************************************************
 *
 * Management-Controller-to-Driver Interface
 *
 **************************************************************************
 */

/* Default RPC timeout for NIC types that don't specify. */
#define MCDI_RPC_TIMEOUT	(10 * HZ)
/* Timeout for acquiring the bus; there may be multiple outstanding requests. */
#define MCDI_ACQUIRE_TIMEOUT	(MCDI_RPC_TIMEOUT * 5)
/* Timeout waiting for a command to be authorised */
#define MCDI_PROXY_TIMEOUT	(10 * HZ)

#ifdef CONFIG_SFC_MCDI_LOGGING
/* printk has this internal limit. Taken from printk.c. */
#define LOG_LINE_MAX		(1024 - 32)
#endif

/* A reboot/assertion causes the MCDI status word to be set after the
 * command word is set or a REBOOT event is sent. If we notice a reboot
 * via these mechanisms then wait 250ms for the status word to be set.
 */
#define MCDI_STATUS_DELAY_US		100
#define MCDI_STATUS_DELAY_COUNT		2500
#define MCDI_STATUS_SLEEP_MS						\
	(MCDI_STATUS_DELAY_US * MCDI_STATUS_DELAY_COUNT / 1000)

#ifdef CONFIG_SFC_MCDI_LOGGING
static bool mcdi_logging_default;
module_param(mcdi_logging_default, bool, 0644);
MODULE_PARM_DESC(mcdi_logging_default,
		 "Enable MCDI logging on newly-probed functions");
#endif

static int efx_mcdi_rpc_async_internal(struct efx_nic *efx,
				       struct efx_mcdi_cmd *cmd,
				       unsigned int *handle,
				       bool immediate_poll,
				       bool immediate_only);
static void efx_mcdi_start_or_queue(struct efx_mcdi_iface *mcdi,
				    bool allow_retry,
				    struct efx_mcdi_copy_buffer *copybuf,
				    struct list_head *cleanup_list);
static void efx_mcdi_cmd_start_or_queue(struct efx_mcdi_iface *mcdi,
					struct efx_mcdi_cmd *cmd,
					struct efx_mcdi_copy_buffer *copybuf,
					struct list_head *cleanup_list);
static int efx_mcdi_cmd_start_or_queue_ext(struct efx_mcdi_iface *mcdi,
					   struct efx_mcdi_cmd *cmd,
					   struct efx_mcdi_copy_buffer *copybuf,
					   bool immediate_only,
					   struct list_head *cleanup_list);
static void efx_mcdi_poll_start(struct efx_mcdi_iface *mcdi,
				struct efx_mcdi_cmd *cmd,
				struct efx_mcdi_copy_buffer *copybuf,
				struct list_head *cleanup_list);
static bool efx_mcdi_poll_once(struct efx_mcdi_iface *mcdi,
			       struct efx_mcdi_cmd *cmd);
static bool efx_mcdi_complete_cmd(struct efx_mcdi_iface *mcdi,
				  struct efx_mcdi_cmd *cmd,
				  struct efx_mcdi_copy_buffer *copybuf,
				  struct list_head *cleanup_list);
static void efx_mcdi_timeout_cmd(struct efx_mcdi_iface *mcdi,
				 struct efx_mcdi_cmd *cmd,
				 struct list_head *cleanup_list);
static void efx_mcdi_reset_during_cmd(struct efx_mcdi_iface *mcdi,
				      struct efx_mcdi_cmd *cmd);
static void efx_mcdi_cmd_work(struct work_struct *work);
static void _efx_mcdi_mode_poll(struct efx_mcdi_iface *mcdi);
static void efx_mcdi_mode_fail(struct efx_nic *efx, struct list_head *cleanup_list);
static void _efx_mcdi_display_error(struct efx_nic *efx, unsigned int cmd,
				    size_t inlen, int raw, int arg, int rc);

static bool efx_cmd_running(struct efx_mcdi_cmd *cmd)
{
	return cmd->state == MCDI_STATE_RUNNING ||
	       cmd->state == MCDI_STATE_RUNNING_CANCELLED;
}

static bool efx_cmd_cancelled(struct efx_mcdi_cmd *cmd)
{
	return cmd->state == MCDI_STATE_RUNNING_CANCELLED ||
	       cmd->state == MCDI_STATE_PROXY_CANCELLED;
}

static void efx_mcdi_cmd_release(struct kref *ref)
{
	kfree(container_of(ref, struct efx_mcdi_cmd, ref));
}

static unsigned int efx_mcdi_cmd_handle(struct efx_mcdi_cmd *cmd)
{
	return cmd->handle;
}

static void _efx_mcdi_remove_cmd(struct efx_mcdi_iface *mcdi,
				 struct efx_mcdi_cmd *cmd,
				 struct list_head *cleanup_list)
{
	/* if cancelled, the completers have already been called */
	if (efx_cmd_cancelled(cmd))
		return;

	if (cmd->atomic_completer)
		cmd->atomic_completer(mcdi->efx, cmd->cookie, cmd->rc,
				      cmd->outbuf, cmd->outlen);
	if (cmd->completer) {
		list_add_tail(&cmd->cleanup_list, cleanup_list);
		++mcdi->outstanding_cleanups;
		kref_get(&cmd->ref);
	}
}

static void efx_mcdi_remove_cmd(struct efx_mcdi_iface *mcdi,
				struct efx_mcdi_cmd *cmd,
				struct list_head *cleanup_list)
{
	list_del(&cmd->list);
	_efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);
	cmd->state = MCDI_STATE_FINISHED;
	kref_put(&cmd->ref, efx_mcdi_cmd_release);
	if (list_empty(&mcdi->cmd_list))
		wake_up(&mcdi->cmd_complete_wq);
}

static unsigned long efx_mcdi_rpc_timeout(struct efx_nic *efx, unsigned int cmd)
{
	if (!efx->type->mcdi_rpc_timeout)
		return MCDI_RPC_TIMEOUT;
	else
		return efx->type->mcdi_rpc_timeout(efx, cmd);
}

int efx_mcdi_init(struct efx_nic *efx)
{
	struct efx_mcdi_iface *mcdi;
	int rc = -ENOMEM;

	efx->mcdi = kzalloc(sizeof(*efx->mcdi), GFP_KERNEL);
	if (!efx->mcdi)
		goto fail;

	mcdi = efx_mcdi(efx);
	mcdi->efx = efx;

#ifdef CONFIG_SFC_MCDI_LOGGING
	mcdi->logging_buffer = kmalloc(LOG_LINE_MAX, GFP_KERNEL);
	if (!mcdi->logging_buffer)
		goto fail2;
	mcdi->logging_enabled = mcdi_logging_default;
#endif
	mcdi->workqueue = create_workqueue("mcdi_wq");
	if (!mcdi->workqueue)
		goto fail3;
	spin_lock_init(&mcdi->iface_lock);
	mcdi->mode = MCDI_MODE_POLL;
	INIT_LIST_HEAD(&mcdi->cmd_list);
	init_waitqueue_head(&mcdi->cmd_complete_wq);

	(void) efx_mcdi_poll_reboot(efx);
	mcdi->new_epoch = true;

	/* Recover from a failed assertion before probing */
	rc = efx_mcdi_handle_assertion(efx);
	if (rc)
		goto fail4;

	/* Let the MC (and BMC, if this is a LOM) know that the driver
	 * is loaded. We should do this before we reset the NIC.
	 * This operation can specify the required firmware variant. This will
	 * fail with EPERM if we are not the primary PF. In this case the
	 * caller should retry with variant "don't care".
	 */
	rc = efx_mcdi_drv_attach(efx, MC_CMD_FW_LOW_LATENCY,
				 &efx->mcdi->fn_flags, false);
	if (rc == -EPERM)
		rc = efx_mcdi_drv_attach(efx, MC_CMD_FW_DONT_CARE,
					 &efx->mcdi->fn_flags, false);
	if (rc) {
		netif_err(efx, probe, efx->net_dev,
			  "Unable to register driver with MCPU\n");
		goto fail4;
	}

	return 0;
fail4:
	destroy_workqueue(mcdi->workqueue);
fail3:
#ifdef CONFIG_SFC_MCDI_LOGGING
	kfree(mcdi->logging_buffer);
fail2:
#endif
	kfree(efx->mcdi);
	efx->mcdi = NULL;
fail:
	return rc;
}

void efx_mcdi_detach(struct efx_nic *efx)
{
	if (!efx->mcdi)
		return;

	if (!efx_nic_hw_unavailable(efx))
		/* Relinquish the device (back to the BMC, if this is a LOM) */
		efx_mcdi_drv_detach(efx);
}

void efx_mcdi_fini(struct efx_nic *efx)
{
	struct efx_mcdi_iface *iface;

	if (!efx->mcdi)
		return;

	efx_mcdi_wait_for_cleanup(efx);

	iface = efx_mcdi(efx);
#ifdef CONFIG_SFC_MCDI_LOGGING
	kfree(iface->logging_buffer);
#endif

	destroy_workqueue(iface->workqueue);
	kfree(efx->mcdi);
	efx->mcdi = NULL;
}

static bool efx_mcdi_reset_cmd_running(struct efx_mcdi_iface *mcdi)
{
	struct efx_mcdi_cmd *cmd;

	list_for_each_entry(cmd, &mcdi->cmd_list, list)
		if (cmd->cmd == MC_CMD_REBOOT &&
		    efx_cmd_running(cmd))
			return true;
	return false;
}

static void efx_mcdi_reboot_detected(struct efx_nic *efx)
{
	struct efx_mcdi_cmd *cmd;
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);

	_efx_mcdi_mode_poll(mcdi);
	list_for_each_entry(cmd, &mcdi->cmd_list, list)
		if (efx_cmd_running(cmd))
			cmd->reboot_seen = true;
	efx->type->mcdi_reboot_detected(efx);
}

static bool efx_mcdi_wait_for_reboot(struct efx_nic *efx)
{
	size_t count;

	for (count = 0; count < MCDI_STATUS_DELAY_COUNT; ++count) {
		if (efx_mcdi_poll_reboot(efx)) {
			efx_mcdi_reboot_detected(efx);
			return true;
		}
		udelay(MCDI_STATUS_DELAY_US);
	}

	return false;
}

static bool efx_mcdi_flushed(struct efx_mcdi_iface *mcdi, bool ignore_cleanups)
{
	bool flushed;

	spin_lock_bh(&mcdi->iface_lock);
	flushed = list_empty(&mcdi->cmd_list) &&
		  (ignore_cleanups || !mcdi->outstanding_cleanups);
	spin_unlock_bh(&mcdi->iface_lock);
	return flushed;
}

/* Wait for outstanding MCDI commands to complete. */
void efx_mcdi_wait_for_cleanup(struct efx_nic *efx)
{
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);

	wait_event(mcdi->cmd_complete_wq,
		   efx_mcdi_flushed(mcdi, false));
}

int efx_mcdi_wait_for_quiescence(struct efx_nic *efx,
				 unsigned int timeout_jiffies)
{
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);

	int rc = wait_event_timeout(mcdi->cmd_complete_wq,
				    efx_mcdi_flushed(mcdi, true),
				    timeout_jiffies);

	if (rc > 0)
		rc = 0;
	else if (rc == 0)
		rc = -ETIMEDOUT;

	return rc;
}

/* Indicate to the MCDI module that we're now sending commands for a new
 * epoch.
 */
void efx_mcdi_post_reset(struct efx_nic *efx)
{
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);

	efx_mcdi_wait_for_cleanup(efx);

	mcdi->new_epoch = true;
}

static void efx_mcdi_send_request(struct efx_nic *efx,
				  struct efx_mcdi_cmd *cmd)
{
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);
#ifdef CONFIG_SFC_MCDI_LOGGING
	char *buf = mcdi->logging_buffer; /* page-sized */
#endif
	efx_dword_t hdr[2];
	size_t hdr_len;
	u32 xflags;
	const efx_dword_t *inbuf = cmd->inbuf;
	size_t inlen = cmd->inlen;

	mcdi->prev_seq = cmd->seq;
	mcdi->seq_held_by[cmd->seq] = cmd;
	mcdi->db_held_by = cmd;
	cmd->started = jiffies;

	xflags = 0;
	if (mcdi->mode == MCDI_MODE_EVENTS)
		xflags |= MCDI_HEADER_XFLAGS_EVREQ;

	if (efx->type->mcdi_max_ver == 1) {
		/* MCDI v1 */
		EFX_POPULATE_DWORD_7(hdr[0],
				     MCDI_HEADER_RESPONSE, 0,
				     MCDI_HEADER_RESYNC, 1,
				     MCDI_HEADER_CODE, cmd->cmd,
				     MCDI_HEADER_DATALEN, inlen,
				     MCDI_HEADER_SEQ, cmd->seq,
				     MCDI_HEADER_XFLAGS, xflags,
				     MCDI_HEADER_NOT_EPOCH, !mcdi->new_epoch);
		hdr_len = 4;
	} else {
		/* MCDI v2 */
		BUG_ON(inlen > MCDI_CTL_SDU_LEN_MAX_V2);
		EFX_POPULATE_DWORD_7(hdr[0],
				     MCDI_HEADER_RESPONSE, 0,
				     MCDI_HEADER_RESYNC, 1,
				     MCDI_HEADER_CODE, MC_CMD_V2_EXTN,
				     MCDI_HEADER_DATALEN, 0,
				     MCDI_HEADER_SEQ, cmd->seq,
				     MCDI_HEADER_XFLAGS, xflags,
				     MCDI_HEADER_NOT_EPOCH, !mcdi->new_epoch);
		EFX_POPULATE_DWORD_2(hdr[1],
				     MC_CMD_V2_EXTN_IN_EXTENDED_CMD, cmd->cmd,
				     MC_CMD_V2_EXTN_IN_ACTUAL_LEN, inlen);
		hdr_len = 8;
	}

#ifdef CONFIG_SFC_MCDI_LOGGING
	if (mcdi->logging_enabled && !WARN_ON_ONCE(!buf)) {
		const efx_dword_t *frags[] = { hdr, inbuf };
		size_t frag_len[] = { hdr_len, round_up(inlen, 4) };
		const efx_dword_t *frag;
		int bytes = 0;
		int i, j;
		unsigned int dcount = 0;
		/* Header length should always be a whole number of dwords,
		 * so scream if it's not.
		 */
		WARN_ON_ONCE(hdr_len % 4);

		for (j = 0; j < ARRAY_SIZE(frags); j++) {
			frag = frags[j];
			for (i = 0;
			     i < frag_len[j] / 4;
			     i++) {
				/* Do not exceeed the internal printk limit.
				 * The string before that is just over 70 bytes.
				 */
				if ((bytes + 75) > LOG_LINE_MAX) {
					netif_info(efx, hw, efx->net_dev,
						   "MCDI RPC REQ:%s \\\n", buf);
					dcount = 0;
					bytes = 0;
				}
				bytes += snprintf(buf + bytes,
						  LOG_LINE_MAX - bytes, " %08x",
						  le32_to_cpu(frag[i].u32[0]));
				dcount++;
			}
		}

		netif_info(efx, hw, efx->net_dev, "MCDI RPC REQ:%s\n", buf);
	}
#endif

	efx->type->mcdi_request(efx, cmd->bufid, hdr, hdr_len, inbuf, inlen);

	mcdi->new_epoch = false;
}

static int efx_mcdi_errno(struct efx_nic *efx, unsigned int mcdi_err)
{
	switch (mcdi_err) {
	case 0:
	case MC_CMD_ERR_PROXY_PENDING:
	case MC_CMD_ERR_QUEUE_FULL:
		return mcdi_err;
#define TRANSLATE_ERROR(name)					\
	case MC_CMD_ERR_ ## name:				\
		return -name;
	TRANSLATE_ERROR(EPERM);
	TRANSLATE_ERROR(ENOENT);
	TRANSLATE_ERROR(EINTR);
	TRANSLATE_ERROR(EAGAIN);
	TRANSLATE_ERROR(EACCES);
	TRANSLATE_ERROR(EBUSY);
	TRANSLATE_ERROR(EINVAL);
	TRANSLATE_ERROR(ERANGE);
	TRANSLATE_ERROR(EDEADLK);
	TRANSLATE_ERROR(ENOSYS);
	TRANSLATE_ERROR(ETIME);
	TRANSLATE_ERROR(EALREADY);
	TRANSLATE_ERROR(ENOSPC);
	TRANSLATE_ERROR(ENOMEM);
#undef TRANSLATE_ERROR
	case MC_CMD_ERR_ENOTSUP:
		return -EOPNOTSUPP;
	case MC_CMD_ERR_ALLOC_FAIL:
		return -ENOBUFS;
	case MC_CMD_ERR_MAC_EXIST:
		return -EADDRINUSE;
	case MC_CMD_ERR_NO_EVB_PORT:
		if (efx->type->is_vf)
			return -EAGAIN;
		fallthrough;
	default:
		return -EPROTO;
	}
}

/* Test and clear MC-rebooted flag for this port/function; reset
 * software state as necessary.
 */
int efx_mcdi_poll_reboot(struct efx_nic *efx)
{
	if (!efx->mcdi)
		return 0;

	return efx->type->mcdi_poll_reboot(efx);
}

static void efx_mcdi_process_cleanup_list(struct efx_nic *efx,
                                          struct list_head *cleanup_list)
{
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);
	unsigned int cleanups = 0;

	while (!list_empty(cleanup_list)) {
		struct efx_mcdi_cmd *cmd =
			list_first_entry(cleanup_list,
					 struct efx_mcdi_cmd, cleanup_list);
		cmd->completer(efx, cmd->cookie, cmd->rc,
			       cmd->outbuf, cmd->outlen);
		list_del(&cmd->cleanup_list);
		kref_put(&cmd->ref, efx_mcdi_cmd_release);
		++cleanups;
	}

	if (cleanups) {
		bool all_done;

		spin_lock_bh(&mcdi->iface_lock);
		EFX_WARN_ON_PARANOID(cleanups > mcdi->outstanding_cleanups);
		all_done = (mcdi->outstanding_cleanups -= cleanups) == 0;
		spin_unlock_bh(&mcdi->iface_lock);
		if (all_done)
			wake_up(&mcdi->cmd_complete_wq);
	}
}

static void _efx_mcdi_cancel_cmd(struct efx_mcdi_iface *mcdi,
				 unsigned int handle,
				 struct list_head *cleanup_list)
{
	struct efx_nic *efx = mcdi->efx;
	struct efx_mcdi_cmd *cmd;

	list_for_each_entry(cmd, &mcdi->cmd_list, list)
		if (efx_mcdi_cmd_handle(cmd) == handle) {
			switch (cmd->state) {
			case MCDI_STATE_QUEUED:
			case MCDI_STATE_RETRY:
				netif_dbg(efx, drv, efx->net_dev,
					  "command %#x inlen %zu cancelled in queue\n",
					  cmd->cmd, cmd->inlen);
				/* if not yet running, properly cancel it */
				cmd->rc = -EPIPE;
				efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);
				break;
			case MCDI_STATE_RUNNING:
			case MCDI_STATE_PROXY:
				netif_dbg(efx, drv, efx->net_dev,
					  "command %#x inlen %zu cancelled after sending\n",
					  cmd->cmd, cmd->inlen);
				/* It's running. We can't cancel it on the MC,
				 * so we need to keep track of it so we can
				 * handle the response. We *also* need to call
				 * the command's completion function, and make
				 * sure it's not called again later, by
				 * marking it as cancelled.
				 */
				cmd->rc = -EPIPE;
				_efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);
				cmd->state = cmd->state == MCDI_STATE_RUNNING ?
					     MCDI_STATE_RUNNING_CANCELLED :
					     MCDI_STATE_PROXY_CANCELLED;
				break;
			case MCDI_STATE_RUNNING_CANCELLED:
			case MCDI_STATE_PROXY_CANCELLED:
				netif_warn(efx, drv, efx->net_dev,
					   "command %#x inlen %zu double cancelled\n",
					   cmd->cmd, cmd->inlen);
				break;
			case MCDI_STATE_FINISHED:
			default:
				/* invalid state? */
				WARN_ON(1);
			}
			break;
		}
}

void efx_mcdi_cancel_cmd(struct efx_nic *efx, unsigned int handle)
{
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);
	LIST_HEAD(cleanup_list);

	spin_lock_bh(&mcdi->iface_lock);
	_efx_mcdi_cancel_cmd(mcdi, handle, &cleanup_list);
	spin_unlock_bh(&mcdi->iface_lock);
	efx_mcdi_process_cleanup_list(efx, &cleanup_list);
}

static void efx_mcdi_proxy_response(struct efx_mcdi_iface *mcdi,
				    struct efx_mcdi_cmd *cmd,
				    int status,
				    struct list_head *cleanup_list)
{
	mcdi->db_held_by = NULL;

	if (status) {
		/* status != 0 means don't retry */
		if (status == -EIO || status == -EINTR)
			efx_mcdi_reset_during_cmd(mcdi, cmd);
		kref_get(&cmd->ref);
		cmd->rc = status;
		efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);
		if (cancel_delayed_work(&cmd->work))
			kref_put(&cmd->ref, efx_mcdi_cmd_release);
		kref_put(&cmd->ref, efx_mcdi_cmd_release);
	} else {
		/* status = 0 means ok to retry */
		efx_mcdi_cmd_start_or_queue(mcdi, cmd, NULL, cleanup_list);
	}
}

static void efx_mcdi_ev_proxy_response(struct efx_nic *efx,
				       u32 handle, int status)
{
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);
	struct efx_mcdi_cmd *cmd;
	bool found = false;
	LIST_HEAD(cleanup_list);

	spin_lock_bh(&mcdi->iface_lock);
	list_for_each_entry(cmd, &mcdi->cmd_list, list)
		if (cmd->state == MCDI_STATE_PROXY &&
		    cmd->proxy_handle == handle) {
			efx_mcdi_proxy_response(mcdi, cmd, status, &cleanup_list);
			found = true;
			break;
		}
	spin_unlock_bh(&mcdi->iface_lock);

	efx_mcdi_process_cleanup_list(efx, &cleanup_list);

	if (!found) {
		netif_err(efx, drv, efx->net_dev,
			  "MCDI proxy unexpected handle %#x\n",
			  handle);
		efx_schedule_reset(efx, RESET_TYPE_WORLD);
	}
}

static void efx_mcdi_cmd_mode_poll(struct efx_mcdi_iface *mcdi,
				   struct efx_mcdi_cmd *cmd)
{
	cmd->polled = true;
	if (cancel_delayed_work(&cmd->work))
		queue_delayed_work(mcdi->workqueue, &cmd->work, 0);
}

static void efx_mcdi_ev_cpl(struct efx_nic *efx, unsigned int seqno,
			    unsigned int datalen, unsigned int mcdi_err)
{
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);
	struct efx_mcdi_cmd *cmd;
	LIST_HEAD(cleanup_list);
	struct efx_mcdi_copy_buffer *copybuf =
		kmalloc(sizeof(struct efx_mcdi_copy_buffer), GFP_ATOMIC);

	spin_lock(&mcdi->iface_lock);
	cmd = mcdi->seq_held_by[seqno];
	if (cmd) {
		if (efx_mcdi_poll_once(mcdi, cmd)) {
			kref_get(&cmd->ref);
			if (efx_mcdi_complete_cmd(mcdi, cmd, copybuf,
						  &cleanup_list))
				if (cancel_delayed_work(&cmd->work))
					kref_put(&cmd->ref,
						 efx_mcdi_cmd_release);
			kref_put(&cmd->ref, efx_mcdi_cmd_release);
		} else {
			/* on some EF100 hardware completion event can overtake
			 * the write to the MCDI buffer.
			 * If so, convert the command to polled mode.
			 * If this is a genuine error, then the
			 * command will eventually time out.
			 */
			if (efx_nic_rev(efx) != EFX_REV_EF100)
				netif_warn(mcdi->efx, drv, mcdi->efx->net_dev,
					   "command %#x inlen %zu event received before response\n",
					   cmd->cmd, cmd->inlen);
			efx_mcdi_cmd_mode_poll(mcdi, cmd);
		}
	} else {
		netif_err(efx, hw, efx->net_dev,
			  "MC response unexpected tx seq 0x%x\n",
			  seqno);
		/* this could theoretically just be a race between command
		 * time out and processing the completion event,  so while not
		 * a good sign, it'd be premature to attempt any recovery.
		 */
	}
	spin_unlock(&mcdi->iface_lock);

	efx_mcdi_process_cleanup_list(efx, &cleanup_list);

	kfree(copybuf);
}

static int
efx_mcdi_check_supported(struct efx_nic *efx, unsigned int cmd, size_t inlen)
{
	if (efx->type->mcdi_max_ver < 0 ||
	     (efx->type->mcdi_max_ver < 2 &&
	      cmd > MC_CMD_CMD_SPACE_ESCAPE_7))
		return -EINVAL;

	if (inlen > MCDI_CTL_SDU_LEN_MAX_V2 ||
	    (efx->type->mcdi_max_ver < 2 &&
	     inlen > MCDI_CTL_SDU_LEN_MAX_V1))
		return -EMSGSIZE;

	return 0;
}

struct efx_mcdi_blocking_data {
	struct kref ref;
	bool done;
	wait_queue_head_t wq;
	int rc;
	efx_dword_t *outbuf;
	size_t outlen;
	size_t outlen_actual;
};

static void efx_mcdi_blocking_data_release(struct kref *ref)
{
	kfree(container_of(ref, struct efx_mcdi_blocking_data, ref));
}

static void efx_mcdi_rpc_completer(struct efx_nic *efx, unsigned long cookie,
				   int rc, efx_dword_t *outbuf,
				   size_t outlen_actual)
{
	struct efx_mcdi_blocking_data *wait_data =
		(struct efx_mcdi_blocking_data *)cookie;

	wait_data->rc = rc;
	memcpy(wait_data->outbuf, outbuf,
	       min(outlen_actual, wait_data->outlen));
	wait_data->outlen_actual = outlen_actual;
	smp_wmb();
	wait_data->done = true;
	wake_up(&wait_data->wq);
	kref_put(&wait_data->ref, efx_mcdi_blocking_data_release);
}

static int efx_mcdi_rpc_sync(struct efx_nic *efx, unsigned int cmd,
			     const efx_dword_t *inbuf, size_t inlen,
			     efx_dword_t *outbuf, size_t outlen,
			     size_t *outlen_actual, bool quiet)
{
	struct efx_mcdi_blocking_data *wait_data;
	struct efx_mcdi_cmd *cmd_item;
	unsigned int handle;
	int rc;

	if (outlen_actual)
		*outlen_actual = 0;

	wait_data = kmalloc(sizeof(*wait_data), GFP_KERNEL);
	if (!wait_data)
		return -ENOMEM;

	cmd_item = kmalloc(sizeof(*cmd_item), GFP_KERNEL);
	if (!cmd_item) {
		kfree(wait_data);
		return -ENOMEM;
	}

	kref_init(&wait_data->ref);
	wait_data->done = false;
	init_waitqueue_head(&wait_data->wq);
	wait_data->outbuf = outbuf;
	wait_data->outlen = outlen;

	kref_init(&cmd_item->ref);
	cmd_item->quiet = quiet;
	cmd_item->cookie = (unsigned long) wait_data;
	cmd_item->atomic_completer = NULL;
	cmd_item->completer = &efx_mcdi_rpc_completer;
	cmd_item->cmd = cmd;
	cmd_item->inlen = inlen;
	cmd_item->inbuf = inbuf;

	/* Claim an extra reference for the completer to put. */
	kref_get(&wait_data->ref);
	rc = efx_mcdi_rpc_async_internal(efx, cmd_item, &handle, true, false);
	if (rc) {
		kref_put(&wait_data->ref, efx_mcdi_blocking_data_release);
		goto out;
	}

	if (!wait_event_timeout(wait_data->wq, wait_data->done,
				MCDI_ACQUIRE_TIMEOUT +
				efx_mcdi_rpc_timeout(efx, cmd)) &&
	    !wait_data->done) {
		netif_err(efx, drv, efx->net_dev,
			  "MC command 0x%x inlen %zu timed out (sync)\n",
			  cmd, inlen);

		efx_mcdi_cancel_cmd(efx, handle);

		wait_data->rc = -ETIMEDOUT;
		wait_data->outlen_actual = 0;
	}

	if (outlen_actual)
		*outlen_actual = wait_data->outlen_actual;
	rc = wait_data->rc;

out:
	kref_put(&wait_data->ref, efx_mcdi_blocking_data_release);

	return rc;
}

int efx_mcdi_rpc_async_ext(struct efx_nic *efx, unsigned int cmd,
			   const efx_dword_t *inbuf, size_t inlen,
			   efx_mcdi_async_completer *atomic_completer,
			   efx_mcdi_async_completer *completer,
			   unsigned long cookie, bool quiet,
			   bool immediate_only, unsigned int *handle)
{
	struct efx_mcdi_cmd *cmd_item =
		kmalloc(sizeof(struct efx_mcdi_cmd) + inlen, GFP_ATOMIC);

	if (!cmd_item)
		return -ENOMEM;

	kref_init(&cmd_item->ref);
	cmd_item->quiet = quiet;
	cmd_item->cookie = cookie;
	cmd_item->completer = completer;
	cmd_item->atomic_completer = atomic_completer;
	cmd_item->cmd = cmd;
	cmd_item->inlen = inlen;
	/* inbuf is probably not valid after return, so take a copy */
	cmd_item->inbuf = (efx_dword_t *) (cmd_item + 1);
	memcpy(cmd_item + 1, inbuf, inlen);

	return efx_mcdi_rpc_async_internal(efx, cmd_item, handle, false,
					   immediate_only);
}

static bool efx_mcdi_get_seq(struct efx_mcdi_iface *mcdi, unsigned char *seq)
{
	*seq = mcdi->prev_seq;
	do {
		*seq = (*seq + 1) % ARRAY_SIZE(mcdi->seq_held_by);
	} while (mcdi->seq_held_by[*seq] && *seq != mcdi->prev_seq);
	return !mcdi->seq_held_by[*seq];
}

static int efx_mcdi_rpc_async_internal(struct efx_nic *efx,
				       struct efx_mcdi_cmd *cmd,
				       unsigned int *handle,
				       bool immediate_poll, bool immediate_only)
{
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);
	struct efx_mcdi_copy_buffer *copybuf;
	LIST_HEAD(cleanup_list);
	int rc;

	rc = efx_mcdi_check_supported(efx, cmd->cmd, cmd->inlen);
	if (rc) {
		kref_put(&cmd->ref, efx_mcdi_cmd_release);
		return rc;
	}
	if (!mcdi || efx->mc_bist_for_other_fn) {
		kref_put(&cmd->ref, efx_mcdi_cmd_release);
		return -ENETDOWN;
	}

	copybuf = immediate_poll ?
		  kmalloc(sizeof(struct efx_mcdi_copy_buffer), GFP_KERNEL) :
		  NULL;

	cmd->mcdi = mcdi;
	INIT_DELAYED_WORK(&cmd->work, efx_mcdi_cmd_work);
	INIT_LIST_HEAD(&cmd->list);
	INIT_LIST_HEAD(&cmd->cleanup_list);
	cmd->proxy_handle = 0;
	cmd->rc = 0;
	cmd->outbuf = NULL;
	cmd->outlen = 0;

	spin_lock_bh(&mcdi->iface_lock);

	if (mcdi->mode == MCDI_MODE_FAIL) {
		spin_unlock_bh(&mcdi->iface_lock);
		kref_put(&cmd->ref, efx_mcdi_cmd_release);
		kfree(copybuf);
		return -ENETDOWN;
	}

	cmd->handle = mcdi->prev_handle++;
	if (handle)
		*handle = efx_mcdi_cmd_handle(cmd);

	list_add_tail(&cmd->list, &mcdi->cmd_list);
	rc = efx_mcdi_cmd_start_or_queue_ext(mcdi, cmd, copybuf, immediate_only,
					     &cleanup_list);
	if (rc) {
		list_del(&cmd->list);
		kref_put(&cmd->ref, efx_mcdi_cmd_release);
	}

	spin_unlock_bh(&mcdi->iface_lock);

	efx_mcdi_process_cleanup_list(efx, &cleanup_list);

	kfree(copybuf);

	return rc;
}

static int efx_mcdi_cmd_start_or_queue_ext(struct efx_mcdi_iface *mcdi,
					   struct efx_mcdi_cmd *cmd,
					   struct efx_mcdi_copy_buffer *copybuf,
					   bool immediate_only,
					   struct list_head *cleanup_list)
{
	struct efx_nic *efx = mcdi->efx;
	u8 seq, bufid;

	if (!mcdi->db_held_by &&
	    efx_mcdi_get_seq(mcdi, &seq) &&
	    efx->type->mcdi_get_buf(efx, &bufid)) {
		cmd->seq = seq;
		cmd->bufid = bufid;
		cmd->polled = mcdi->mode == MCDI_MODE_POLL;
		cmd->reboot_seen = false;
		efx_mcdi_send_request(efx, cmd);
		cmd->state = MCDI_STATE_RUNNING;

		if (cmd->polled)
			efx_mcdi_poll_start(mcdi, cmd, copybuf, cleanup_list);
		else {
			kref_get(&cmd->ref);
			queue_delayed_work(mcdi->workqueue, &cmd->work,
					   efx_mcdi_rpc_timeout(efx, cmd->cmd));
		}
	} else if (immediate_only) {
		return -EAGAIN;
	} else {
		cmd->state = MCDI_STATE_QUEUED;
	}

	return 0;
}

static void efx_mcdi_cmd_start_or_queue(struct efx_mcdi_iface *mcdi,
                                        struct efx_mcdi_cmd *cmd,
                                        struct efx_mcdi_copy_buffer *copybuf,
                                        struct list_head *cleanup_list)
{
	/* when immediate_only=false this can only return success */
	(void) efx_mcdi_cmd_start_or_queue_ext(mcdi, cmd, copybuf, false,
					       cleanup_list);
}

/* try to advance other commands */
static void efx_mcdi_start_or_queue(struct efx_mcdi_iface *mcdi,
				    bool allow_retry,
				    struct efx_mcdi_copy_buffer *copybuf,
				    struct list_head *cleanup_list)
{
	struct efx_mcdi_cmd *cmd, *tmp;

	list_for_each_entry_safe(cmd, tmp, &mcdi->cmd_list, list)
		if (cmd->state == MCDI_STATE_QUEUED ||
		    (cmd->state == MCDI_STATE_RETRY && allow_retry))
			efx_mcdi_cmd_start_or_queue(mcdi, cmd, copybuf,
						    cleanup_list);
}

static void efx_mcdi_poll_start(struct efx_mcdi_iface *mcdi,
				struct efx_mcdi_cmd *cmd,
				struct efx_mcdi_copy_buffer *copybuf,
				struct list_head *cleanup_list)
{
	/* Poll for completion. Poll quickly (once a us) for the 1st jiffy,
	 * because generally mcdi responses are fast. After that, back off
	 * and poll once a jiffy (approximately)
	 */
	int spins = copybuf ? USER_TICK_USEC : 0;

	while (spins) {
		if (efx_mcdi_poll_once(mcdi, cmd)) {
			efx_mcdi_complete_cmd(mcdi, cmd, copybuf, cleanup_list);
			return;
		}

		--spins;
		udelay(1);
	}

	/* didn't get a response in the first jiffy;
	 * schedule poll after another jiffy
	 */
	kref_get(&cmd->ref);
	queue_delayed_work(mcdi->workqueue, &cmd->work, 1);
}

static bool efx_mcdi_poll_once(struct efx_mcdi_iface *mcdi,
			       struct efx_mcdi_cmd *cmd)
{
	struct efx_nic *efx = mcdi->efx;

	/* complete or error, either way return true */
	return efx_nic_hw_unavailable(efx) ||
	       efx->type->mcdi_poll_response(efx, cmd->bufid);
}

static unsigned long efx_mcdi_poll_interval(struct efx_mcdi_iface *mcdi,
					    struct efx_mcdi_cmd *cmd)
{
	if (time_before(jiffies, cmd->started + msecs_to_jiffies(10)))
		return msecs_to_jiffies(1);
	else if (time_before(jiffies, cmd->started + msecs_to_jiffies(100)))
		return msecs_to_jiffies(10);
	else if (time_before(jiffies, cmd->started + msecs_to_jiffies(1000)))
		return msecs_to_jiffies(100);
	else
		return msecs_to_jiffies(1000);
}

static bool efx_mcdi_check_timeout(struct efx_mcdi_iface *mcdi,
				   struct efx_mcdi_cmd *cmd)
{
	return time_after(jiffies, cmd->started +
				   efx_mcdi_rpc_timeout(mcdi->efx, cmd->cmd));
}

static void efx_mcdi_proxy_timeout_cmd(struct efx_mcdi_iface *mcdi,
				       struct efx_mcdi_cmd *cmd,
				       struct list_head *cleanup_list)
{
	struct efx_nic *efx = mcdi->efx;

	netif_err(efx, drv, efx->net_dev, "MCDI proxy timeout (handle %#x)\n",
		  cmd->proxy_handle);

	cmd->rc = -ETIMEDOUT;
	efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);

	efx_mcdi_mode_fail(efx, cleanup_list);
	efx_schedule_reset(efx, RESET_TYPE_MCDI_TIMEOUT);
}

static void efx_mcdi_cmd_work(struct work_struct *context)
{
	struct efx_mcdi_cmd *cmd =
#if !defined(EFX_USE_KCOMPAT) || !defined(EFX_NEED_WORK_API_WRAPPERS)
		container_of(context, struct efx_mcdi_cmd, work.work);
#else
		container_of(context, struct efx_mcdi_cmd, work);
#endif
	struct efx_mcdi_iface *mcdi = cmd->mcdi;
	struct efx_mcdi_copy_buffer *copybuf =
		kmalloc(sizeof(struct efx_mcdi_copy_buffer), GFP_KERNEL);
	LIST_HEAD(cleanup_list);

	spin_lock_bh(&mcdi->iface_lock);

	if (cmd->state == MCDI_STATE_FINISHED) {
		/* The command is done and this is a race between the
		 * completion in another thread and the work item running.
		 * All processing been done, so just release it.
		 */
		spin_unlock_bh(&mcdi->iface_lock);
		kref_put(&cmd->ref, efx_mcdi_cmd_release);
		kfree(copybuf);
		return;
	}

	EFX_WARN_ON_PARANOID(cmd->state == MCDI_STATE_QUEUED);
	EFX_WARN_ON_PARANOID(cmd->state == MCDI_STATE_RETRY);

	/* if state PROXY, then proxy time out */
	if (cmd->state == MCDI_STATE_PROXY) {
		efx_mcdi_proxy_timeout_cmd(mcdi, cmd, &cleanup_list);
	/* else running, check for completion */
	} else if (efx_mcdi_poll_once(mcdi, cmd)) {
		if (!cmd->polled) {
			/* check whether the event is pending on EVQ0 */
			if (efx_nic_mcdi_ev_pending(efx_get_channel(mcdi->efx, 0)))
				netif_err(mcdi->efx, drv, mcdi->efx->net_dev,
					  "MC command 0x%x inlen %zu mode %d completed without an interrupt after %u ms\n",
					  cmd->cmd, cmd->inlen,
					  cmd->polled ? MCDI_MODE_POLL : MCDI_MODE_EVENTS,
					  jiffies_to_msecs(jiffies - cmd->started));
			else
				netif_err(mcdi->efx, drv, mcdi->efx->net_dev,
					  "MC command 0x%x inlen %zu mode %d completed without an event after %u ms\n",
					  cmd->cmd, cmd->inlen,
					  cmd->polled ? MCDI_MODE_POLL : MCDI_MODE_EVENTS,
					  jiffies_to_msecs(jiffies - cmd->started));
			/* things are going wrong.
			 * switch to polled mode so we tear down faster.
			 */
			_efx_mcdi_mode_poll(mcdi);
		}
		efx_mcdi_complete_cmd(mcdi, cmd, copybuf, &cleanup_list);
	/* then check for timeout. If evented, it must have timed out */
	} else if (!cmd->polled || efx_mcdi_check_timeout(mcdi, cmd)) {
		efx_mcdi_timeout_cmd(mcdi, cmd, &cleanup_list);
	/* else reschedule for another poll */
	} else {
		kref_get(&cmd->ref);
		queue_delayed_work(mcdi->workqueue, &cmd->work,
				   efx_mcdi_poll_interval(mcdi, cmd));
	}

	spin_unlock_bh(&mcdi->iface_lock);

	kref_put(&cmd->ref, efx_mcdi_cmd_release);

	efx_mcdi_process_cleanup_list(mcdi->efx, &cleanup_list);

	kfree(copybuf);
}

static void efx_mcdi_reset_during_cmd(struct efx_mcdi_iface *mcdi,
				      struct efx_mcdi_cmd *cmd)
{
	struct efx_nic *efx = mcdi->efx;
	bool reset_running = efx_mcdi_reset_cmd_running(mcdi);

	if (!reset_running)
		netif_err(efx, hw, efx->net_dev,
			  "Command %#x inlen %zu cancelled by MC reboot\n",
			  cmd->cmd, cmd->inlen);
	/* consume the reset notification if we haven't already */
	if (!cmd->reboot_seen && efx_mcdi_wait_for_reboot(efx))
		if (!reset_running)
			efx_schedule_reset(efx, RESET_TYPE_MC_FAILURE);
}

/* Returns true if the MCDI module is finished with the command.
 * (examples of false would be if the command was proxied, or it was
 * rejected by the MC due to lack of resources and requeued).
 */
static bool efx_mcdi_complete_cmd(struct efx_mcdi_iface *mcdi,
				  struct efx_mcdi_cmd *cmd,
				  struct efx_mcdi_copy_buffer *copybuf,
				  struct list_head *cleanup_list)
{
	struct efx_nic *efx = mcdi->efx;
	int rc;
	size_t resp_hdr_len, resp_data_len;
	unsigned int respseq, respcmd, error;
	efx_dword_t hdr;
	efx_dword_t *outbuf = copybuf ? copybuf->buffer : NULL;
	u8 bufid = cmd->bufid;
	bool completed = false;

	/* ensure the command can't go away before this function returns */
	kref_get(&cmd->ref);

	efx->type->mcdi_read_response(efx, bufid, &hdr, 0, 4);
	respseq = EFX_DWORD_FIELD(hdr, MCDI_HEADER_SEQ);
	respcmd = EFX_DWORD_FIELD(hdr, MCDI_HEADER_CODE);
	error = EFX_DWORD_FIELD(hdr, MCDI_HEADER_ERROR);

	if (respcmd != MC_CMD_V2_EXTN) {
		resp_hdr_len = 4;
		resp_data_len = EFX_DWORD_FIELD(hdr, MCDI_HEADER_DATALEN);
	} else {
		efx->type->mcdi_read_response(efx, bufid, &hdr, 4, 4);
		respcmd = EFX_DWORD_FIELD(hdr, MC_CMD_V2_EXTN_IN_EXTENDED_CMD);
		resp_hdr_len = 8;
		resp_data_len =
			EFX_DWORD_FIELD(hdr, MC_CMD_V2_EXTN_IN_ACTUAL_LEN);
	}

#ifdef CONFIG_SFC_MCDI_LOGGING
	if (mcdi->logging_enabled && !WARN_ON_ONCE(!mcdi->logging_buffer)) {
		size_t len;
		int bytes = 0;
		int i;
		unsigned int dcount = 0;
		char *log = mcdi->logging_buffer;

		WARN_ON_ONCE(resp_hdr_len % 4);
		/* MCDI_DECLARE_BUF ensures that underlying buffer is padded
		 * to dword size, and the MCDI buffer is always dword size
		 */
		len = resp_hdr_len / 4 + DIV_ROUND_UP(resp_data_len, 4);

		for (i = 0; i < len; i++) {
			if ((bytes + 75) > LOG_LINE_MAX) {
				netif_info(efx, hw, efx->net_dev,
						"MCDI RPC RESP:%s \\\n", log);
				dcount = 0;
				bytes = 0;
			}
			efx->type->mcdi_read_response(efx, bufid,
						      &hdr, (i * 4), 4);
			bytes += snprintf(log + bytes, LOG_LINE_MAX - bytes,
					" %08x", le32_to_cpu(hdr.u32[0]));
			dcount++;
		}

		netif_info(efx, hw, efx->net_dev, "MCDI RPC RESP:%s\n", log);
	}
#endif

	if (error && resp_data_len == 0) {
		/* MC rebooted during command */
		efx_mcdi_reset_during_cmd(mcdi, cmd);
		rc = -EIO;
	} else if (!outbuf) {
		rc = -ENOMEM;
	} else {
		if (WARN_ON_ONCE(error && resp_data_len < 4))
			resp_data_len = 4;

		efx->type->mcdi_read_response(efx, bufid, outbuf,
					      resp_hdr_len, resp_data_len);

		if (error) {
			rc = EFX_DWORD_FIELD(outbuf[0], EFX_DWORD_0);
			if (!cmd->quiet) {
				int err_arg = 0;

#ifdef WITH_MCDI_V2
				if (resp_data_len >= MC_CMD_ERR_ARG_OFST + 4) {
					efx->type->mcdi_read_response(
						efx, bufid, &hdr,
						resp_hdr_len +
							MC_CMD_ERR_ARG_OFST, 4);
					err_arg = EFX_DWORD_VAL(hdr);
				}
#endif
				_efx_mcdi_display_error(efx, cmd->cmd,
							cmd->inlen, rc, err_arg,
							efx_mcdi_errno(efx, rc));
			}
			rc = efx_mcdi_errno(efx, rc);
		} else {
			rc = 0;
		}
	}

	if (rc == MC_CMD_ERR_PROXY_PENDING) {
		if (mcdi->db_held_by != cmd || cmd->proxy_handle ||
		    resp_data_len < MC_CMD_ERR_PROXY_PENDING_HANDLE_OFST + 4) {
			/* The MC shouldn't return the doorbell early and then
			 * proxy. It also shouldn't return PROXY_PENDING with
			 * no handle or proxy a command that's already been
			 * proxied. Schedule an flr to reset the state.
			 */
			if (mcdi->db_held_by != cmd)
				netif_err(efx, drv, efx->net_dev,
					  "MCDI proxy pending with early db return\n");
			if (cmd->proxy_handle)
				netif_err(efx, drv, efx->net_dev,
					  "MCDI proxy pending twice\n");
			if (resp_data_len <
			    MC_CMD_ERR_PROXY_PENDING_HANDLE_OFST + 4)
				netif_err(efx, drv, efx->net_dev,
					  "MCDI proxy pending with no handle\n");
			cmd->rc = -EIO;
			efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);
			completed = true;

			efx_mcdi_mode_fail(efx, cleanup_list);
			efx_schedule_reset(efx, RESET_TYPE_MCDI_TIMEOUT);
		} else {
			/* keep the doorbell. no commands
			 * can be issued until the proxy response.
			 */
			cmd->state = MCDI_STATE_PROXY;
			efx->type->mcdi_read_response(efx, bufid, &hdr,
				resp_hdr_len +
					MC_CMD_ERR_PROXY_PENDING_HANDLE_OFST,
				4);
			cmd->proxy_handle = EFX_DWORD_FIELD(hdr, EFX_DWORD_0);
			kref_get(&cmd->ref);
			queue_delayed_work(mcdi->workqueue, &cmd->work,
					   MCDI_PROXY_TIMEOUT);
		}
	} else {
		/* free doorbell */
		if (mcdi->db_held_by == cmd)
			mcdi->db_held_by = NULL;

		if (efx_cmd_cancelled(cmd)) {
			list_del(&cmd->list);
			kref_put(&cmd->ref, efx_mcdi_cmd_release);
			completed = true;
		} else if (rc == MC_CMD_ERR_QUEUE_FULL) {
			cmd->state = MCDI_STATE_RETRY;
		} else {
			cmd->rc = rc;
			cmd->outbuf = outbuf;
			cmd->outlen = outbuf ? resp_data_len : 0;
			efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);
			completed = true;
		}
	}

	/* free sequence number and buffer */
	mcdi->seq_held_by[cmd->seq] = NULL;
	efx->type->mcdi_put_buf(efx, bufid);

	efx_mcdi_start_or_queue(mcdi, rc != MC_CMD_ERR_QUEUE_FULL,
				NULL, cleanup_list);

	/* wake up anyone waiting for flush */
	wake_up(&mcdi->cmd_complete_wq);

	kref_put(&cmd->ref, efx_mcdi_cmd_release);

	return completed;
}

static void efx_mcdi_timeout_cmd(struct efx_mcdi_iface *mcdi,
				 struct efx_mcdi_cmd *cmd,
				 struct list_head *cleanup_list)
{
	struct efx_nic *efx = mcdi->efx;

	netif_err(efx, drv, efx->net_dev,
		  "MC command 0x%x inlen %zu state %d mode %d timed out after %u ms\n",
		  cmd->cmd, cmd->inlen, cmd->state,
		  cmd->polled ? MCDI_MODE_POLL : MCDI_MODE_EVENTS,
		  jiffies_to_msecs(jiffies - cmd->started));

	efx->type->mcdi_put_buf(efx, cmd->bufid);

	cmd->rc = -ETIMEDOUT;
	efx_mcdi_remove_cmd(mcdi, cmd, cleanup_list);

	efx_mcdi_mode_fail(efx, cleanup_list);
	efx_schedule_reset(efx, RESET_TYPE_MCDI_TIMEOUT);
}

/**
 * efx_mcdi_rpc - Issue an MCDI command and wait for completion
 * @efx: NIC through which to issue the command
 * @cmd: Command type number
 * @inbuf: Command parameters
 * @inlen: Length of command parameters, in bytes.  Must be a multiple
 *	of 4 and no greater than %MCDI_CTL_SDU_LEN_MAX_V1.
 * @outbuf: Response buffer.  May be %NULL if @outlen is 0.
 * @outlen: Length of response buffer, in bytes.  If the actual
 *	reponse is longer than @outlen & ~3, it will be truncated
 *	to that length.
 * @outlen_actual: Pointer through which to return the actual response
 *	length.  May be %NULL if this is not needed.
 *
 * This function may sleep and therefore must be called in process
 * context.
 *
 * Return: A negative error code, or zero if successful.  The error
 *	code may come from the MCDI response or may indicate a failure
 *	to communicate with the MC.  In the former case, the response
 *	will still be copied to @outbuf and *@outlen_actual will be
 *	set accordingly.  In the latter case, *@outlen_actual will be
 *	set to zero.
 */
int efx_mcdi_rpc(struct efx_nic *efx, unsigned int cmd,
		 const efx_dword_t *inbuf, size_t inlen,
		 efx_dword_t *outbuf, size_t outlen,
		 size_t *outlen_actual)
{
	return efx_mcdi_rpc_sync(efx, cmd, inbuf, inlen, outbuf, outlen,
				 outlen_actual, false);
}

/* Normally, on receiving an error code in the MCDI response,
 * efx_mcdi_rpc will log an error message containing (among other
 * things) the raw error code, by means of efx_mcdi_display_error.
 * This _quiet version suppresses that; if the caller wishes to log
 * the error conditionally on the return code, it should call this
 * function and is then responsible for calling efx_mcdi_display_error
 * as needed.
 */
int efx_mcdi_rpc_quiet(struct efx_nic *efx, unsigned int cmd,
		       const efx_dword_t *inbuf, size_t inlen,
		       efx_dword_t *outbuf, size_t outlen,
		       size_t *outlen_actual)
{
	return efx_mcdi_rpc_sync(efx, cmd, inbuf, inlen, outbuf, outlen,
				 outlen_actual, true);
}

/**
 * efx_mcdi_rpc_async - Schedule an MCDI command to run asynchronously
 * @efx: NIC through which to issue the command
 * @cmd: Command type number
 * @inbuf: Command parameters
 * @inlen: Length of command parameters, in bytes
 * @outlen: Length to allocate for response buffer, in bytes
 * @complete: Function to be called on completion or cancellation.
 * @cookie: Arbitrary value to be passed to @complete.
 *
 * This function does not sleep and therefore may be called in atomic
 * context.  It will fail if event queues are disabled or if MCDI
 * event completions have been disabled due to an error.
 *
 * If it succeeds, the @complete function will be called exactly once
 * in atomic context, when one of the following occurs:
 * (a) the completion event is received (in NAPI context)
 * (b) event queues are disabled (in the process that disables them)
 * (c) the request times-out (in timer context)
 */
int
efx_mcdi_rpc_async(struct efx_nic *efx, unsigned int cmd,
		   const efx_dword_t *inbuf, size_t inlen,
		   efx_mcdi_async_completer *complete, unsigned long cookie)
{
	return efx_mcdi_rpc_async_ext(efx, cmd, inbuf, inlen, NULL,
				      complete, cookie, false, false, NULL);
}

int efx_mcdi_rpc_async_quiet(struct efx_nic *efx, unsigned int cmd,
			     const efx_dword_t *inbuf, size_t inlen,
			     efx_mcdi_async_completer *complete,
			     unsigned long cookie)
{
	return efx_mcdi_rpc_async_ext(efx, cmd, inbuf, inlen, NULL,
				      complete, cookie, true, false, NULL);
}

/**
 * efx_mcdi_rpc_client - issue an MCDI command on a non-base client
 * This is a superset of the functionality of efx_mcdi_rpc(), adding:
 * @client_id: A dynamic client ID on which to send this MCDI command, or
 *	MC_CMD_CLIENT_ID_SELF to send the command to the base client (which
 *	makes this function identical to efx_mcdi_rpc()).
 *
 * The caller must provide space for 12 additional bytes (beyond inlen) in the
 * memory at inbuf since inbuf may be modified in-situ.
 * MCDI_DECLARE_PROXYABLE_BUF should be used for this. This function may sleep
 * and therefore must be called in process context.
 */
int efx_mcdi_rpc_client(struct efx_nic *efx, u32 client_id, unsigned int cmd,
			efx_dword_t *inbuf, size_t inlen, efx_dword_t *outbuf,
			size_t outlen, size_t *outlen_actual)
{
	MCDI_DECLARE_BUF(client_cmd, MC_CMD_CLIENT_CMD_IN_LEN);
	efx_dword_t inner_mcdi[2];

	if (client_id == MC_CMD_CLIENT_ID_SELF)
		return efx_mcdi_rpc(efx, cmd, inbuf, inlen, outbuf, outlen,
		                    outlen_actual);

	MCDI_SET_DWORD(client_cmd, CLIENT_CMD_IN_CLIENT_ID, client_id);
	/* There's lots of other fields in the MCDI header, but
	 * they're all ignored for proxied commands */
	EFX_POPULATE_DWORD_2(inner_mcdi[0],
		MCDI_HEADER_CODE, MC_CMD_V2_EXTN,
		MCDI_HEADER_DATALEN, 0);
	EFX_POPULATE_DWORD_2(inner_mcdi[1],
		MC_CMD_V2_EXTN_IN_EXTENDED_CMD, cmd,
		MC_CMD_V2_EXTN_IN_ACTUAL_LEN, inlen);
	memmove((char*)inbuf + sizeof(client_cmd) + sizeof(inner_mcdi),
	         inbuf, inlen);
	memcpy(inbuf, client_cmd, sizeof(client_cmd));
	memcpy((char*)inbuf + sizeof(client_cmd),
	       inner_mcdi, sizeof(inner_mcdi));
	inlen += sizeof(client_cmd) + sizeof(inner_mcdi);
	return efx_mcdi_rpc(efx, MC_CMD_CLIENT_CMD, inbuf, inlen,
	                    outbuf, outlen, outlen_actual);
}

static void _efx_mcdi_display_error(struct efx_nic *efx, unsigned int cmd,
				    size_t inlen, int raw, int arg, int rc)
{
	if (efx->net_dev)
		netif_cond_dbg(efx, hw, efx->net_dev,
			       rc == -EPERM || efx_nic_hw_unavailable(efx), err,
			       "MC command 0x%x inlen %d failed rc=%d (raw=%d) arg=%d\n",
			       cmd, (int)inlen, rc, raw, arg);
	else
		pci_dbg(efx->pci_dev,
			"MC command 0x%x inlen %d failed rc=%d (raw=%d) arg=%d\n",
			cmd, (int)inlen, rc, raw, arg);
}

void efx_mcdi_display_error(struct efx_nic *efx, unsigned int cmd,
			    size_t inlen, efx_dword_t *outbuf,
			    size_t outlen, int rc)
{
	int code = 0, arg = 0;

	if (outlen >= MC_CMD_ERR_CODE_OFST + 4)
		code = MCDI_DWORD(outbuf, ERR_CODE);
#ifdef WITH_MCDI_V2
	if (outlen >= MC_CMD_ERR_ARG_OFST + 4)
		arg = MCDI_DWORD(outbuf, ERR_ARG);
#endif

	_efx_mcdi_display_error(efx, cmd, inlen, code, arg, rc);
}

/* Switch to polled MCDI completions. */
static void _efx_mcdi_mode_poll(struct efx_mcdi_iface *mcdi)
{
	/* If already in polling mode, nothing to do.
	 * If in fail-fast state, don't switch to polled completion, FLR
	 * recovery will do that later.
	 */
	if (mcdi->mode == MCDI_MODE_EVENTS) {
		struct efx_mcdi_cmd *cmd;

		mcdi->mode = MCDI_MODE_POLL;

		list_for_each_entry(cmd, &mcdi->cmd_list, list)
			if (efx_cmd_running(cmd) && !cmd->polled) {
				netif_dbg(mcdi->efx, drv, mcdi->efx->net_dev,
					  "converting command %#x inlen %zu to polled mode\n",
					  cmd->cmd, cmd->inlen);
				efx_mcdi_cmd_mode_poll(mcdi, cmd);
			}
	}
}

void efx_mcdi_mode_poll(struct efx_nic *efx)
{
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);

	if (!mcdi)
		return;

	spin_lock_bh(&mcdi->iface_lock);
	_efx_mcdi_mode_poll(mcdi);
	spin_unlock_bh(&mcdi->iface_lock);
}

void efx_mcdi_mode_event(struct efx_nic *efx)
{
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);

	if (!mcdi)
		return;

	spin_lock_bh(&mcdi->iface_lock);
	/* If already in event completion mode, nothing to do.
	 * If in fail-fast state, don't switch to event completion.  FLR
	 * recovery will do that later.
	 */
	if (mcdi->mode == MCDI_MODE_POLL)
		mcdi->mode = MCDI_MODE_EVENTS;
	spin_unlock_bh(&mcdi->iface_lock);
}

/* Set MCDI mode to fail to prevent any new commands, then cancel any
 * outstanding commands.
 * Caller must hold the mcdi iface_lock.
 */
static void efx_mcdi_mode_fail(struct efx_nic *efx, struct list_head *cleanup_list)
{
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);
	struct efx_mcdi_cmd *cmd;

	mcdi->mode = MCDI_MODE_FAIL;

	while (!list_empty(&mcdi->cmd_list)) {
		cmd = list_first_entry(&mcdi->cmd_list, struct efx_mcdi_cmd,
				       list);
		_efx_mcdi_cancel_cmd(mcdi, efx_mcdi_cmd_handle(cmd), cleanup_list);
	}
}

static void efx_mcdi_ev_death(struct efx_nic *efx, bool bist)
{
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);

	if (bist) {
		efx->mc_bist_for_other_fn = true;
		efx->type->mcdi_record_bist_event(efx);
	}
	spin_lock(&mcdi->iface_lock);
	efx_mcdi_reboot_detected(efx);
	/* if this is the result of a MC_CMD_REBOOT then don't schedule reset */
	if (bist || !efx_mcdi_reset_cmd_running(mcdi))
		efx_schedule_reset(efx, bist ? RESET_TYPE_MC_BIST :
					       RESET_TYPE_MC_FAILURE);
	spin_unlock(&mcdi->iface_lock);
}

bool efx_mcdi_process_event(struct efx_channel *channel,
			    efx_qword_t *event)
{
	struct efx_nic *efx = channel->efx;
	int code = EFX_QWORD_FIELD(*event, MCDI_EVENT_CODE);
	u32 data = EFX_QWORD_FIELD(*event, MCDI_EVENT_DATA);

	switch (code) {
	case MCDI_EVENT_CODE_BADSSERT:
		netif_err(efx, hw, efx->net_dev,
			  "MC watchdog or assertion failure at 0x%x\n", data);
		efx_mcdi_ev_death(efx, false);
		return true;

	case MCDI_EVENT_CODE_PMNOTICE:
		netif_info(efx, wol, efx->net_dev, "MCDI PM event.\n");
		return true;

	case MCDI_EVENT_CODE_CMDDONE:
		efx_mcdi_ev_cpl(efx,
				MCDI_EVENT_FIELD(*event, CMDDONE_SEQ),
				MCDI_EVENT_FIELD(*event, CMDDONE_DATALEN),
				MCDI_EVENT_FIELD(*event, CMDDONE_ERRNO));
		return true;
        case MCDI_EVENT_CODE_PROXY_RESPONSE:
                efx_mcdi_ev_proxy_response(efx,
                                MCDI_EVENT_FIELD(*event, PROXY_RESPONSE_HANDLE),
                                MCDI_EVENT_FIELD(*event, PROXY_RESPONSE_RC));
                return true;
	case MCDI_EVENT_CODE_SCHEDERR:
		netif_dbg(efx, hw, efx->net_dev,
			   "MC Scheduler alert (0x%x)\n", data);
		return true;
	case MCDI_EVENT_CODE_REBOOT:
	case MCDI_EVENT_CODE_MC_REBOOT: /* XXX should handle this differently? */
		efx_mcdi_ev_death(efx, false);
		return true;
	case MCDI_EVENT_CODE_MC_BIST:
		netif_info(efx, hw, efx->net_dev, "MC entered BIST mode\n");
		efx_mcdi_ev_death(efx, true);
		return true;
	}

	return false;
}

/**************************************************************************
 *
 * Specific request functions
 *
 **************************************************************************
 */

void efx_mcdi_print_fwver(struct efx_nic *efx, char *buf, size_t len)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_VERSION_OUT_LEN);
	size_t outlength;
	const __le16 *ver_words;
	size_t offset;
	int rc;

	BUILD_BUG_ON(MC_CMD_GET_VERSION_IN_LEN != 0);
	rc = efx_mcdi_rpc(efx, MC_CMD_GET_VERSION, NULL, 0,
			  outbuf, sizeof(outbuf), &outlength);
	if (rc)
		goto fail;
	if (outlength < MC_CMD_GET_VERSION_OUT_LEN) {
		rc = -EIO;
		goto fail;
	}

	ver_words = (__le16 *)MCDI_PTR(outbuf, GET_VERSION_OUT_VERSION);
	offset = snprintf(buf, len, "%u.%u.%u.%u",
			  le16_to_cpu(ver_words[0]), le16_to_cpu(ver_words[1]),
			  le16_to_cpu(ver_words[2]), le16_to_cpu(ver_words[3]));

	/* EF10 may have multiple datapath firmware variants within a
	 * single version.  Report which variants are running.
	 */
	if (efx_nic_rev(efx) == EFX_REV_HUNT_A0) {
		MCDI_DECLARE_BUF(capbuf, MC_CMD_GET_CAPABILITIES_OUT_LEN);
		unsigned int rx_id, tx_id;
		size_t caplen;

		BUILD_BUG_ON(MC_CMD_GET_CAPABILITIES_IN_LEN != 0);
		rc = efx_mcdi_rpc(efx, MC_CMD_GET_CAPABILITIES, NULL, 0,
				  capbuf, sizeof(capbuf), &caplen);
		if (rc)
			goto fail;
		if (caplen < MC_CMD_GET_CAPABILITIES_OUT_LEN) {
			rc = -EIO;
			goto fail;
		}

		rx_id = MCDI_WORD(capbuf, GET_CAPABILITIES_OUT_RX_DPCPU_FW_ID);
		tx_id = MCDI_WORD(capbuf, GET_CAPABILITIES_OUT_TX_DPCPU_FW_ID);

		offset += snprintf(buf + offset, len - offset, " rx%x tx%x",
				   rx_id, tx_id);

		/* It's theoretically possible for the string to exceed 31
		 * characters, though in practice the first three version
		 * components are short enough that this doesn't happen.
		 */
		if (WARN_ON(offset >= len))
			buf[0] = 0;
	}

	return;

fail:
	pci_err(efx->pci_dev, "%s: failed rc=%d\n", __func__, rc);
	buf[0] = 0;
}

void efx_mcdi_print_fw_bundle_ver(struct efx_nic *efx, char *buf, size_t len)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_VERSION_V5_OUT_LEN);
	MCDI_DECLARE_BUF(inbuf, MC_CMD_GET_VERSION_EXT_IN_LEN);
	unsigned int flags;
	size_t outlength;
	int rc;

	MCDI_SET_DWORD(inbuf, GET_VERSION_EXT_IN_EXT_FLAGS, 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_VERSION, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlength);
	if (rc)
		goto fail;
	if (outlength < MC_CMD_GET_VERSION_V5_OUT_LEN) {
		rc = -EIO;
		pci_err(efx->pci_dev, "%s: failed rc=%d\n", __func__, rc);
		goto fail;
	}

	flags = MCDI_DWORD(outbuf, GET_VERSION_V5_OUT_FLAGS);
	if (flags & BIT(MC_CMD_GET_VERSION_V5_OUT_BUNDLE_VERSION_PRESENT_LBN)) {
		const __le32 *ver_dwords = (__le32 *)MCDI_PTR(outbuf,
			GET_VERSION_V5_OUT_BUNDLE_VERSION);
		size_t needed;

		needed = snprintf(buf, len, "%u.%u.%u.%u",
				  le32_to_cpu(ver_dwords[0]),
				  le32_to_cpu(ver_dwords[1]),
				  le32_to_cpu(ver_dwords[2]),
				  le32_to_cpu(ver_dwords[3]));
		if (WARN_ON(needed >= len))
			goto fail;
	} else {
		strlcpy(buf, "N/A", len);
	}

	return;

fail:
	buf[0] = 0;
}

static int efx_mcdi_drv_attach_attempt(struct efx_nic *efx,
				       u32 fw_variant, u32 new_state,
				       u32 *flags, bool reattach)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_DRV_ATTACH_IN_V2_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_DRV_ATTACH_EXT_OUT_LEN);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, DRV_ATTACH_IN_NEW_STATE, new_state);
	MCDI_SET_DWORD(inbuf, DRV_ATTACH_IN_UPDATE, 1);
	MCDI_SET_DWORD(inbuf, DRV_ATTACH_IN_FIRMWARE_ID, fw_variant);

	strlcpy(MCDI_PTR(inbuf, DRV_ATTACH_IN_V2_DRIVER_VERSION),
		EFX_DRIVER_VERSION, MC_CMD_DRV_ATTACH_IN_V2_DRIVER_VERSION_LEN);

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_DRV_ATTACH, inbuf, sizeof(inbuf),
				outbuf, sizeof(outbuf), &outlen);

	/* If we're not the primary PF, trying to ATTACH with a firmware
	 * variant other than MC_CMD_FW_DONT_CARE will fail with EPERM.
	 *
	 * The firmware can also return EOPNOTSUPP, EBUSY or EINVAL if we've
	 * asked for some combinations of VI spreading. Such failures are
	 * handled at a slightly higher level.
	 *
	 * In these cases we can return without logging an error.
	 */
	if (rc == -EPERM || rc == -EOPNOTSUPP || rc == -EBUSY || rc == -EINVAL) {
		netif_dbg(efx, probe, efx->net_dev,
			  "efx_mcdi_drv_attach failed: %d\n", rc);
		return rc;
	}

	if (!reattach && (rc || outlen < MC_CMD_DRV_ATTACH_OUT_LEN)) {
		efx_mcdi_display_error(efx, MC_CMD_DRV_ATTACH, sizeof(inbuf),
				       outbuf, outlen, rc);
		if (outlen < MC_CMD_DRV_ATTACH_OUT_LEN)
			rc = -EIO;
		return rc;
	}

	if (new_state & (1 << MC_CMD_DRV_ATTACH_IN_ATTACH_LBN)) {
		/* Were we already attached? */
		u32 old_state = MCDI_DWORD(outbuf, DRV_ATTACH_OUT_OLD_STATE);

		if ((old_state & (1 << MC_CMD_DRV_ATTACH_IN_ATTACH_LBN)) &&
		    !reattach)
			netif_warn(efx, probe, efx->net_dev,
				   "efx_mcdi_drv_attach attached when already attached\n");
	}

	if (!flags)
		return rc;

	if (outlen >= MC_CMD_DRV_ATTACH_EXT_OUT_LEN)
		*flags = MCDI_DWORD(outbuf, DRV_ATTACH_EXT_OUT_FUNC_FLAGS);
	else
		/* Mock up flags for older NICs */
		*flags = 1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_LINKCTRL |
			 1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_TRUSTED |
			 (efx_port_num(efx) == 0) <<
			 MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_PRIMARY;

	return rc;
}

static bool efx_mcdi_drv_attach_bad_spreading(u32 flags)
{
	/* We don't support full VI spreading, only the tx-only version. */
	return flags & (1 << MC_CMD_DRV_ATTACH_EXT_OUT_FLAG_VI_SPREADING_ENABLED);
}

int efx_mcdi_drv_detach(struct efx_nic *efx)
{
	return efx_mcdi_drv_attach_attempt(efx, MC_CMD_FW_DONT_CARE, 0, NULL,
					   false);
}

int efx_mcdi_drv_attach(struct efx_nic *efx, u32 fw_variant, u32 *out_flags,
			bool reattach)
{
#ifdef EFX_NOT_UPSTREAM
	bool request_spreading = false;
#endif
	u32 flags;
	u32 in;
	int rc;

	in = (1 << MC_CMD_DRV_ATTACH_IN_ATTACH_LBN) |
	     (1 << MC_CMD_DRV_ATTACH_IN_WANT_V2_LINKCHANGES_LBN);

#ifdef EFX_NOT_UPSTREAM
	/* We request TX-only VI spreading. The firmware will only provide
	 * this if we're a single port device where this is actually useful.
	 */
	if (efx->performance_profile == EFX_PERFORMANCE_PROFILE_THROUGHPUT) {
		request_spreading = true;
		in |= 1 << MC_CMD_DRV_ATTACH_IN_WANT_TX_ONLY_SPREADING_LBN;
	}
#endif

	rc = efx_mcdi_drv_attach_attempt(efx, fw_variant, in, &flags, reattach);

#ifdef EFX_NOT_UPSTREAM
	/* If we requested spreading and the firmware failed to provide that
	 * we should retry the attach without the request.
	 */
	if (request_spreading && (rc == -EINVAL || rc == -EOPNOTSUPP)) {
		pci_dbg(efx->pci_dev,
			"%s failed (%d) when requesting VI spreading mode; retrying\n",
			__func__, rc);

		/* Retry without asking for spreading. */
		in &= ~(1 << MC_CMD_DRV_ATTACH_IN_WANT_TX_ONLY_SPREADING_LBN);
		rc = efx_mcdi_drv_attach_attempt(efx, fw_variant,
						 in, &flags, reattach);
	}
#endif

	if (rc == 0 && efx_mcdi_drv_attach_bad_spreading(flags)) {
		efx_mcdi_drv_detach(efx);
		pci_err(efx->pci_dev,
			"%s gave unsupported VI spreading mode\n", __func__);
		rc = -EINVAL;
	}

	if (rc == 0) {
		pci_dbg(efx->pci_dev,
			"%s attached with flags %#x\n", __func__, flags);
		if (out_flags)
			*out_flags = flags;
	}

	return rc;
}

int efx_mcdi_get_board_perm_mac(struct efx_nic *efx, u8 *mac_address)
{
	return efx_mcdi_get_board_cfg(efx, 0, mac_address, NULL, NULL);
}

int efx_mcdi_get_board_cfg(struct efx_nic *efx, int port_num, u8 *mac_address,
			   u16 *fw_subtype_list, u32 *capabilities)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_BOARD_CFG_OUT_LENMAX);
	size_t outlen, i;
	int rc;

	BUILD_BUG_ON(MC_CMD_GET_BOARD_CFG_IN_LEN != 0);
	/* we need __aligned(2) for ether_addr_copy */
	BUILD_BUG_ON(MC_CMD_GET_BOARD_CFG_OUT_MAC_ADDR_BASE_PORT0_OFST & 1);
	BUILD_BUG_ON(MC_CMD_GET_BOARD_CFG_OUT_MAC_ADDR_BASE_PORT1_OFST & 1);

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_BOARD_CFG, NULL, 0,
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		goto fail;

	if (outlen < MC_CMD_GET_BOARD_CFG_OUT_LENMIN) {
		rc = -EIO;
		goto fail;
	}

	if (mac_address)
		ether_addr_copy(mac_address,
				port_num ?
				MCDI_PTR(outbuf, GET_BOARD_CFG_OUT_MAC_ADDR_BASE_PORT1) :
				MCDI_PTR(outbuf, GET_BOARD_CFG_OUT_MAC_ADDR_BASE_PORT0));
	if (fw_subtype_list) {
		for (i = 0;
		     i < MCDI_VAR_ARRAY_LEN(outlen,
					    GET_BOARD_CFG_OUT_FW_SUBTYPE_LIST);
		     i++)
			fw_subtype_list[i] = MCDI_ARRAY_WORD(
				outbuf, GET_BOARD_CFG_OUT_FW_SUBTYPE_LIST, i);
		for (; i < MC_CMD_GET_BOARD_CFG_OUT_FW_SUBTYPE_LIST_MAXNUM; i++)
			fw_subtype_list[i] = 0;
	}
	if (capabilities) {
		if (port_num)
			*capabilities = MCDI_DWORD(outbuf,
					GET_BOARD_CFG_OUT_CAPABILITIES_PORT1);
		else
			*capabilities = MCDI_DWORD(outbuf,
					GET_BOARD_CFG_OUT_CAPABILITIES_PORT0);
	}

	return 0;

fail:
	netif_err(efx, hw, efx->net_dev, "%s: failed rc=%d len=%d\n",
		  __func__, rc, (int)outlen);

	return rc;
}

int efx_mcdi_log_ctrl(struct efx_nic *efx, bool evq, bool uart, u32 dest_evq)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_LOG_CTRL_IN_LEN);
	u32 dest = 0;
	int rc;

	if (uart)
		dest |= MC_CMD_LOG_CTRL_IN_LOG_DEST_UART;
	if (evq)
		dest |= MC_CMD_LOG_CTRL_IN_LOG_DEST_EVQ;

	MCDI_SET_DWORD(inbuf, LOG_CTRL_IN_LOG_DEST, dest);
	MCDI_SET_DWORD(inbuf, LOG_CTRL_IN_LOG_DEST_EVQ, dest_evq);

	BUILD_BUG_ON(MC_CMD_LOG_CTRL_OUT_LEN != 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_LOG_CTRL, inbuf, sizeof(inbuf),
			  NULL, 0, NULL);
	return rc;
}

void efx_mcdi_log_puts(struct efx_nic *efx, const char *text)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_PUTS_IN_LENMAX);
	struct timespec64 tv;
	int inlen;

	ktime_get_real_ts64(&tv);
	inlen = snprintf(MCDI_PTR(inbuf, PUTS_IN_STRING),
			 MC_CMD_PUTS_IN_STRING_MAXNUM,
			 "{%lld %s}", (long long int)tv.tv_sec,
			 (text ? text : ""));
	/* Count the NULL byte as well */
	inlen += MC_CMD_PUTS_IN_STRING_OFST + 1;

	MCDI_SET_DWORD(inbuf, PUTS_IN_DEST, 1);
	efx_mcdi_rpc_quiet(efx, MC_CMD_PUTS, inbuf, inlen, NULL, 0, NULL);
}

int efx_mcdi_nvram_types(struct efx_nic *efx, u32 *nvram_types_out)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_NVRAM_TYPES_OUT_LEN);
	size_t outlen;
	int rc;

	BUILD_BUG_ON(MC_CMD_NVRAM_TYPES_IN_LEN != 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_NVRAM_TYPES, NULL, 0,
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		goto fail;
	if (outlen < MC_CMD_NVRAM_TYPES_OUT_LEN) {
		rc = -EIO;
		goto fail;
	}

	*nvram_types_out = MCDI_DWORD(outbuf, NVRAM_TYPES_OUT_TYPES);
	return 0;

fail:
	if (rc != -EPERM)
		netif_err(efx, hw, efx->net_dev, "%s: failed rc=%d\n",
			  __func__, rc);
	return rc;
}

/* This function finds types using the new NVRAM_PARTITIONS mcdi. */
static int efx_new_mcdi_nvram_types(struct efx_nic *efx, u32 *number,
                                    u32 *nvram_types)
{
	efx_dword_t *outbuf = kzalloc(MC_CMD_NVRAM_PARTITIONS_OUT_LENMAX_MCDI2,
	                              GFP_KERNEL);
	size_t outlen;
	int rc;

	if (!outbuf)
		return -ENOMEM;

	BUILD_BUG_ON(MC_CMD_NVRAM_PARTITIONS_IN_LEN != 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_NVRAM_PARTITIONS, NULL, 0,
			  outbuf, MC_CMD_NVRAM_PARTITIONS_OUT_LENMAX_MCDI2, &outlen);
	if (rc)
		goto fail;

	*number = MCDI_DWORD(outbuf, NVRAM_PARTITIONS_OUT_NUM_PARTITIONS);

	memcpy(nvram_types, MCDI_PTR(outbuf, NVRAM_PARTITIONS_OUT_TYPE_ID),
	       *number * sizeof(u32));

fail:
	kfree(outbuf);
	return rc;
}

#define EFX_MCDI_NVRAM_DEFAULT_WRITE_LEN 128

int efx_mcdi_nvram_info(struct efx_nic *efx, unsigned int type,
			size_t *size_out, size_t *erase_size_out,
			size_t *write_size_out, bool *protected_out)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_NVRAM_INFO_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_NVRAM_INFO_V2_OUT_LEN);
	size_t write_size = 0;
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, NVRAM_INFO_IN_TYPE, type);

	rc = efx_mcdi_rpc(efx, MC_CMD_NVRAM_INFO, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		goto fail;
	if (outlen < MC_CMD_NVRAM_INFO_OUT_LEN) {
		rc = -EIO;
		goto fail;
	}

	if (outlen >= MC_CMD_NVRAM_INFO_V2_OUT_LEN)
		write_size = MCDI_DWORD(outbuf, NVRAM_INFO_V2_OUT_WRITESIZE);
	else
		write_size = EFX_MCDI_NVRAM_DEFAULT_WRITE_LEN;

	*write_size_out = write_size;
	*size_out = MCDI_DWORD(outbuf, NVRAM_INFO_OUT_SIZE);
	*erase_size_out = MCDI_DWORD(outbuf, NVRAM_INFO_OUT_ERASESIZE);
	*protected_out = !!(MCDI_DWORD(outbuf, NVRAM_INFO_OUT_FLAGS) &
				(1 << MC_CMD_NVRAM_INFO_OUT_PROTECTED_LBN));
	return 0;

fail:
	netif_err(efx, hw, efx->net_dev, "%s: failed rc=%d\n", __func__, rc);
	return rc;
}

static int efx_mcdi_nvram_test(struct efx_nic *efx, unsigned int type)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_NVRAM_TEST_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_NVRAM_TEST_OUT_LEN);
	int rc;

	MCDI_SET_DWORD(inbuf, NVRAM_TEST_IN_TYPE, type);

	rc = efx_mcdi_rpc(efx, MC_CMD_NVRAM_TEST, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), NULL);
	if (rc)
		return rc;

	switch (MCDI_DWORD(outbuf, NVRAM_TEST_OUT_RESULT)) {
	case MC_CMD_NVRAM_TEST_PASS:
	case MC_CMD_NVRAM_TEST_NOTSUPP:
		return 0;
	default:
		netif_err(efx, hw, efx->net_dev, "%s: failed type=%u\n",
			  __func__, type);
		return -EIO;
	}
}

/* This function tests all nvram partitions */
int efx_mcdi_nvram_test_all(struct efx_nic *efx)
{
	u32 *nvram_types = kzalloc(MC_CMD_NVRAM_PARTITIONS_OUT_LENMAX_MCDI2,
	                           GFP_KERNEL);
	unsigned int number;
	int rc, i;

	if (!nvram_types)
		return -ENOMEM;

	rc = efx_new_mcdi_nvram_types(efx, &number, nvram_types);
	if (rc)
		goto fail;

	/* Require at least one check */
	rc = -EAGAIN;

	for (i = 0; i < number; i++) {
		if (nvram_types[i] == NVRAM_PARTITION_TYPE_PARTITION_MAP ||
		    nvram_types[i] == NVRAM_PARTITION_TYPE_DYNAMIC_CONFIG)
			continue;

		rc = efx_mcdi_nvram_test(efx, nvram_types[i]);
		if (rc)
			goto fail;
	}

fail:
	kfree(nvram_types);
	return rc;
}

/* Returns 1 if an assertion was read, 0 if no assertion had fired,
 * negative on error.
 */
static int efx_mcdi_read_assertion(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_GET_ASSERTS_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_ASSERTS_OUT_LEN);
	unsigned int flags, index;
	const char *reason;
	size_t outlen;
	int retry;
	int rc;

	/* Attempt to read any stored assertion state before we reboot
	 * the mcfw out of the assertion handler. Retry twice, once
	 * because a boot-time assertion might cause this command to fail
	 * with EINTR. And once again because GET_ASSERTS can race with
	 * MC_CMD_REBOOT running on the other port. */
	retry = 2;
	do {
		MCDI_SET_DWORD(inbuf, GET_ASSERTS_IN_CLEAR, 1);
		rc = efx_mcdi_rpc_quiet(efx, MC_CMD_GET_ASSERTS,
					inbuf, MC_CMD_GET_ASSERTS_IN_LEN,
					outbuf, sizeof(outbuf), &outlen);
		if (rc == -EPERM)
			return 0;
	} while ((rc == -EINTR || rc == -EIO) && retry-- > 0);

	if (rc) {
		efx_mcdi_display_error(efx, MC_CMD_GET_ASSERTS,
				       MC_CMD_GET_ASSERTS_IN_LEN, outbuf,
				       outlen, rc);
		return rc;
	}
	if (outlen < MC_CMD_GET_ASSERTS_OUT_LEN)
		return -EIO;

	/* Print out any recorded assertion state */
	flags = MCDI_DWORD(outbuf, GET_ASSERTS_OUT_GLOBAL_FLAGS);
	if (flags == MC_CMD_GET_ASSERTS_FLAGS_NO_FAILS)
		return 0;

	reason = (flags == MC_CMD_GET_ASSERTS_FLAGS_SYS_FAIL)
		? "system-level assertion"
		: (flags == MC_CMD_GET_ASSERTS_FLAGS_THR_FAIL)
		? "thread-level assertion"
		: (flags == MC_CMD_GET_ASSERTS_FLAGS_WDOG_FIRED)
		? "watchdog reset"
		: "unknown assertion";
	netif_err(efx, hw, efx->net_dev,
		  "MCPU %s at PC = 0x%.8x in thread 0x%.8x\n", reason,
		  MCDI_DWORD(outbuf, GET_ASSERTS_OUT_SAVED_PC_OFFS),
		  MCDI_DWORD(outbuf, GET_ASSERTS_OUT_THREAD_OFFS));

	/* Print out the registers */
	for (index = 0;
	     index < MC_CMD_GET_ASSERTS_OUT_GP_REGS_OFFS_NUM;
	     index++)
		netif_err(efx, hw, efx->net_dev, "R%.2d (?): 0x%.8x\n",
			  1 + index,
			  MCDI_ARRAY_DWORD(outbuf, GET_ASSERTS_OUT_GP_REGS_OFFS,
					   index));

	return 1;
}

static int efx_mcdi_exit_assertion(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_REBOOT_IN_LEN);
	int rc;

	/* If the MC is running debug firmware, it might now be
	 * waiting for a debugger to attach, but we just want it to
	 * reboot.  We set a flag that makes the command a no-op if it
	 * has already done so.
	 * The MCDI will thus return either 0 or -EIO.
	 */
	BUILD_BUG_ON(MC_CMD_REBOOT_OUT_LEN != 0);
	MCDI_SET_DWORD(inbuf, REBOOT_IN_FLAGS,
		       MC_CMD_REBOOT_FLAGS_AFTER_ASSERTION);
	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_REBOOT, inbuf, MC_CMD_REBOOT_IN_LEN,
				NULL, 0, NULL);
	if (rc == -EIO)
		rc = 0;
	if (rc)
		efx_mcdi_display_error(efx, MC_CMD_REBOOT, MC_CMD_REBOOT_IN_LEN,
				       NULL, 0, rc);
	return rc;
}

int efx_mcdi_handle_assertion(struct efx_nic *efx)
{
	int rc;

	rc = efx_mcdi_read_assertion(efx);
	if (rc <= 0)
		return rc;

	return efx_mcdi_exit_assertion(efx);
}

void efx_mcdi_set_id_led(struct efx_nic *efx, enum efx_led_mode mode)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_SET_ID_LED_IN_LEN);
	int rc;

	BUILD_BUG_ON(EFX_LED_OFF != MC_CMD_LED_OFF);
	BUILD_BUG_ON(EFX_LED_ON != MC_CMD_LED_ON);
	BUILD_BUG_ON(EFX_LED_DEFAULT != MC_CMD_LED_DEFAULT);

	BUILD_BUG_ON(MC_CMD_SET_ID_LED_OUT_LEN != 0);

	MCDI_SET_DWORD(inbuf, SET_ID_LED_IN_STATE, mode);

	rc = efx_mcdi_rpc(efx, MC_CMD_SET_ID_LED, inbuf, sizeof(inbuf),
			  NULL, 0, NULL);
}

static int efx_mcdi_reset_func(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_ENTITY_RESET_IN_LEN);
	int rc;

	BUILD_BUG_ON(MC_CMD_ENTITY_RESET_OUT_LEN != 0);
	MCDI_POPULATE_DWORD_1(inbuf, ENTITY_RESET_IN_FLAG,
			      ENTITY_RESET_IN_FUNCTION_RESOURCE_RESET, 1);
	rc = efx_mcdi_rpc(efx, MC_CMD_ENTITY_RESET, inbuf, sizeof(inbuf),
			  NULL, 0, NULL);
	return rc;
}

static int efx_mcdi_reset_mc(struct efx_nic *efx)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_REBOOT_IN_LEN);
	int rc;

	BUILD_BUG_ON(MC_CMD_REBOOT_OUT_LEN != 0);
	MCDI_SET_DWORD(inbuf, REBOOT_IN_FLAGS, 0);
	rc = efx_mcdi_rpc(efx, MC_CMD_REBOOT, inbuf, sizeof(inbuf),
			  NULL, 0, NULL);
	/* White is black, and up is down */
	if (rc == -EIO)
		return 0;
	if (rc == 0)
		rc = -EIO;
	return rc;
}

static int efx_flr(struct efx_nic *efx)
{
	struct efx_mcdi_iface *mcdi = efx_mcdi(efx);
	LIST_HEAD(cleanup_list);
	u16 seq;
	int rc;

	netif_dbg(efx, drv, efx->net_dev, "Beginning FLR\n");

	rc = pci_reset_function(efx->pci_dev);
	if (rc)
		return rc;

	if (!mcdi)
		return 0;

	spin_lock_bh(&mcdi->iface_lock);
	while (!list_empty(&mcdi->cmd_list)) {
		struct efx_mcdi_cmd *cmd =
			list_first_entry(&mcdi->cmd_list,
					 struct efx_mcdi_cmd, list);

		netif_dbg(efx, drv, efx->net_dev,
			  "aborting command %#x inlen %zu due to FLR\n",
			  cmd->cmd, cmd->inlen);

		kref_get(&cmd->ref);

		cmd->rc = -EIO;

		if (efx_cmd_running(cmd))
			efx->type->mcdi_put_buf(efx, cmd->bufid);

		efx_mcdi_remove_cmd(mcdi, cmd, &cleanup_list);

		if (cancel_delayed_work(&cmd->work))
			kref_put(&cmd->ref, efx_mcdi_cmd_release);

		kref_put(&cmd->ref, efx_mcdi_cmd_release);
	}

	mcdi->db_held_by = NULL;
	for (seq = 0; seq < ARRAY_SIZE(mcdi->seq_held_by); ++seq)
		mcdi->seq_held_by[seq] = NULL;
	mcdi->mode = MCDI_MODE_POLL;

	spin_unlock_bh(&mcdi->iface_lock);

	netif_dbg(efx, drv, efx->net_dev, "Cleaning up for FLR\n");

	efx_mcdi_process_cleanup_list(efx, &cleanup_list);

	netif_dbg(efx, drv, efx->net_dev, "FLR complete\n");

	return 0;
}

int efx_mcdi_reset(struct efx_nic *efx, enum reset_type method)
{
	int rc;

	/* If MCDI is down, we can't handle_assertion */
	if (method == RESET_TYPE_MCDI_TIMEOUT)
		return efx_flr(efx);

	/* Recover from a failed assertion pre-reset */
	rc = efx_mcdi_handle_assertion(efx);
	if (rc)
		return rc;

	if (method == RESET_TYPE_DATAPATH || method == RESET_TYPE_MC_BIST)
		rc = 0;
	else if (method == RESET_TYPE_WORLD)
		rc = efx_mcdi_reset_mc(efx);
	else
		rc = efx_mcdi_reset_func(efx);

	/* This will have reset our stats; clear our fixup values. */
	if (rc == 0) {
		efx->rx_nodesc_drops_total = 0;
		efx->rx_nodesc_drops_while_down = 0;
	}

	return rc;
}

static int efx_mcdi_wol_filter_set(struct efx_nic *efx, u32 type,
				   const u8 *mac, int *id_out)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_WOL_FILTER_SET_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_WOL_FILTER_SET_OUT_LEN);
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, WOL_FILTER_SET_IN_WOL_TYPE, type);
	MCDI_SET_DWORD(inbuf, WOL_FILTER_SET_IN_FILTER_MODE,
		       MC_CMD_FILTER_MODE_SIMPLE);
	ether_addr_copy(MCDI_PTR(inbuf, WOL_FILTER_SET_IN_MAGIC_MAC), mac);

	rc = efx_mcdi_rpc(efx, MC_CMD_WOL_FILTER_SET, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		goto fail;

	if (outlen < MC_CMD_WOL_FILTER_SET_OUT_LEN) {
		rc = -EIO;
		goto fail;
	}

	*id_out = (int)MCDI_DWORD(outbuf, WOL_FILTER_SET_OUT_FILTER_ID);

	return 0;

fail:
	*id_out = -1;
	netif_err(efx, hw, efx->net_dev, "%s: failed rc=%d\n", __func__, rc);
	return rc;

}

int
efx_mcdi_wol_filter_set_magic(struct efx_nic *efx,  const u8 *mac, int *id_out)
{
	return efx_mcdi_wol_filter_set(efx, MC_CMD_WOL_TYPE_MAGIC, mac, id_out);
}

int efx_mcdi_wol_filter_get_magic(struct efx_nic *efx, int *id_out)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_WOL_FILTER_GET_OUT_LEN);
	size_t outlen;
	int rc;

	rc = efx_mcdi_rpc(efx, MC_CMD_WOL_FILTER_GET, NULL, 0,
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		goto fail;

	if (outlen < MC_CMD_WOL_FILTER_GET_OUT_LEN) {
		rc = -EIO;
		goto fail;
	}

	*id_out = (int)MCDI_DWORD(outbuf, WOL_FILTER_GET_OUT_FILTER_ID);

	return 0;

fail:
	*id_out = -1;
	netif_err(efx, hw, efx->net_dev, "%s: failed rc=%d\n", __func__, rc);
	return rc;
}

int efx_mcdi_wol_filter_remove(struct efx_nic *efx, int id)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_WOL_FILTER_REMOVE_IN_LEN);
	int rc;

	MCDI_SET_DWORD(inbuf, WOL_FILTER_REMOVE_IN_FILTER_ID, (u32)id);

	rc = efx_mcdi_rpc(efx, MC_CMD_WOL_FILTER_REMOVE, inbuf, sizeof(inbuf),
			  NULL, 0, NULL);
	return rc;
}

int efx_mcdi_wol_filter_reset(struct efx_nic *efx)
{
	int rc;

	rc = efx_mcdi_rpc(efx, MC_CMD_WOL_FILTER_RESET, NULL, 0, NULL, 0, NULL);
	return rc;
}

int efx_mcdi_set_workaround(struct efx_nic *efx, u32 type, bool enabled,
			    unsigned int *flags)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_WORKAROUND_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_WORKAROUND_EXT_OUT_LEN);
	size_t outlen;
	int rc;

	BUILD_BUG_ON(MC_CMD_WORKAROUND_OUT_LEN != 0);
	MCDI_SET_DWORD(inbuf, WORKAROUND_IN_TYPE, type);
	MCDI_SET_DWORD(inbuf, WORKAROUND_IN_ENABLED, enabled);
	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_WORKAROUND, inbuf, sizeof(inbuf),
				outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;

	if (!flags)
		return 0;

	if (outlen >= MC_CMD_WORKAROUND_EXT_OUT_LEN)
		*flags = MCDI_DWORD(outbuf, WORKAROUND_EXT_OUT_FLAGS);
	else
		*flags = 0;

	return 0;
}

int efx_mcdi_get_workarounds(struct efx_nic *efx, unsigned int *impl_out,
			     unsigned int *enabled_out)
{
	MCDI_DECLARE_BUF(outbuf, MC_CMD_GET_WORKAROUNDS_OUT_LEN);
	size_t outlen;
	int rc;

	rc = efx_mcdi_rpc(efx, MC_CMD_GET_WORKAROUNDS, NULL, 0,
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		goto fail;

	if (outlen < MC_CMD_GET_WORKAROUNDS_OUT_LEN) {
		rc = -EIO;
		goto fail;
	}

	if (impl_out)
		*impl_out = MCDI_DWORD(outbuf, GET_WORKAROUNDS_OUT_IMPLEMENTED);

	if (enabled_out)
		*enabled_out = MCDI_DWORD(outbuf, GET_WORKAROUNDS_OUT_ENABLED);

	return 0;

fail:
	/* Older firmware lacks GET_WORKAROUNDS and this isn't especially
	 * terrifying.  The call site will have to deal with it though.
	 */
	netif_cond_dbg(efx, hw, efx->net_dev, rc == -ENOSYS, err,
		       "%s: failed rc=%d\n", __func__, rc);
	return rc;
}

int efx_mcdi_get_privilege_mask(struct efx_nic *efx, u32 *mask)
{
	MCDI_DECLARE_BUF(fi_outbuf, MC_CMD_GET_FUNCTION_INFO_OUT_LEN);
	MCDI_DECLARE_BUF(pm_inbuf, MC_CMD_PRIVILEGE_MASK_IN_LEN);
	MCDI_DECLARE_BUF(pm_outbuf, MC_CMD_PRIVILEGE_MASK_OUT_LEN);
	size_t outlen;
	u16 pf, vf;
	int rc;

	if (!efx || !mask)
		return -EINVAL;

	/* Get our function number */
	rc = efx_mcdi_rpc(efx, MC_CMD_GET_FUNCTION_INFO, NULL, 0,
			fi_outbuf, MC_CMD_GET_FUNCTION_INFO_OUT_LEN, &outlen);
	if (rc != 0)
		return rc;
	if (outlen < MC_CMD_GET_FUNCTION_INFO_OUT_LEN)
		return -EIO;

	pf = MCDI_DWORD(fi_outbuf, GET_FUNCTION_INFO_OUT_PF);
	vf = MCDI_DWORD(fi_outbuf, GET_FUNCTION_INFO_OUT_VF);

	MCDI_POPULATE_DWORD_2(pm_inbuf, PRIVILEGE_MASK_IN_FUNCTION,
			PRIVILEGE_MASK_IN_FUNCTION_PF, pf,
			PRIVILEGE_MASK_IN_FUNCTION_VF, vf);

	rc = efx_mcdi_rpc(efx, MC_CMD_PRIVILEGE_MASK,
			pm_inbuf, sizeof(pm_inbuf),
			pm_outbuf, sizeof(pm_outbuf), &outlen);

	if (rc != 0)
		return rc;
	if (outlen < MC_CMD_PRIVILEGE_MASK_OUT_LEN)
		return -EIO;

	*mask = MCDI_DWORD(pm_outbuf, PRIVILEGE_MASK_OUT_OLD_MASK);

	return 0;
}

/**
 * efx_mcdi_rpc_proxy_cmd - Do MCDI command throught proxy
 * @efx: NIC through which to issue the command
 * @pf: Target physical function
 * @vf: Target virtual function or MC_CMD_PROXY_CMD_IN_VF_NULL
 * @request_buf: MCDI request to be done
 * @request_size: MCDI request size
 * @response_buf: Buffer to put MCDI response (including header) to. May
 *	be updated in the case of failure as well.
 * @response_size: Size of the buffer for MCDI response
 * @response_size_actual: Optional location to put actual response size
 */
int efx_mcdi_rpc_proxy_cmd(struct efx_nic *efx, u32 pf, u32 vf,
			   const void *request_buf, size_t request_size,
			   void *response_buf, size_t response_size,
			   size_t *response_size_actual)
{
	size_t inlen;
	efx_dword_t *inbuf;
	int rc;

	BUILD_BUG_ON(MC_CMD_PROXY_CMD_IN_LEN % sizeof(*inbuf));
	BUILD_BUG_ON(MC_CMD_PROXY_CMD_OUT_LEN != 0);

	if (request_size % sizeof(*inbuf) != 0)
		return -EINVAL;

	inlen = MC_CMD_PROXY_CMD_IN_LEN + request_size;
	inbuf = kzalloc(inlen, GFP_KERNEL);
	if (!inbuf)
		return -ENOMEM;

	MCDI_POPULATE_DWORD_2(inbuf, PROXY_CMD_IN_TARGET,
			      PROXY_CMD_IN_TARGET_PF, pf,
			      PROXY_CMD_IN_TARGET_VF, vf);

	/* Proxied command should be located just after PROXY_CMD */
	memcpy(&inbuf[MC_CMD_PROXY_CMD_IN_LEN / sizeof(*inbuf)],
	       request_buf, request_size);

	rc = efx_mcdi_rpc(efx, MC_CMD_PROXY_CMD, inbuf, inlen,
			  response_buf, response_size,
			  response_size_actual);

	kfree(inbuf);

	return rc;
}


#define EFX_MCDI_NVRAM_LEN_MAX 128

int efx_mcdi_nvram_update_start(struct efx_nic *efx, unsigned int type)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_NVRAM_UPDATE_START_V2_IN_LEN);
	int rc;

	MCDI_SET_DWORD(inbuf, NVRAM_UPDATE_START_IN_TYPE, type);
	MCDI_POPULATE_DWORD_1(inbuf, NVRAM_UPDATE_START_V2_IN_FLAGS,
			      NVRAM_UPDATE_START_V2_IN_FLAG_REPORT_VERIFY_RESULT, 1);

	BUILD_BUG_ON(MC_CMD_NVRAM_UPDATE_START_OUT_LEN != 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_NVRAM_UPDATE_START, inbuf, sizeof(inbuf),
			  NULL, 0, NULL);

	return rc;
}

int efx_mcdi_nvram_read(struct efx_nic *efx, unsigned int type,
			loff_t offset, u8 *buffer, size_t length)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_NVRAM_READ_IN_V2_LEN);
	MCDI_DECLARE_BUF(outbuf,
			 MC_CMD_NVRAM_READ_OUT_LEN(EFX_MCDI_NVRAM_LEN_MAX));
	size_t outlen;
	int rc;

	MCDI_SET_DWORD(inbuf, NVRAM_READ_IN_TYPE, type);
	MCDI_SET_DWORD(inbuf, NVRAM_READ_IN_OFFSET, offset);
	MCDI_SET_DWORD(inbuf, NVRAM_READ_IN_LENGTH, length);
	MCDI_SET_DWORD(inbuf, NVRAM_READ_IN_V2_MODE,
			      MC_CMD_NVRAM_READ_IN_V2_DEFAULT);

	rc = efx_mcdi_rpc(efx, MC_CMD_NVRAM_READ, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (rc)
		return rc;

	memcpy(buffer, MCDI_PTR(outbuf, NVRAM_READ_OUT_READ_BUFFER), length);
	return 0;
}

int efx_mcdi_nvram_write(struct efx_nic *efx, unsigned int type,
			 loff_t offset, const u8 *buffer, size_t length)
{
	efx_dword_t *inbuf;
	size_t inlen;
	int rc;

	inlen = ALIGN(MC_CMD_NVRAM_WRITE_IN_LEN(length), 4);
	inbuf = kzalloc(inlen, GFP_KERNEL);
	if (!inbuf)
		return -ENOMEM;

	MCDI_SET_DWORD(inbuf, NVRAM_WRITE_IN_TYPE, type);
	MCDI_SET_DWORD(inbuf, NVRAM_WRITE_IN_OFFSET, offset);
	MCDI_SET_DWORD(inbuf, NVRAM_WRITE_IN_LENGTH, length);
	memcpy(MCDI_PTR(inbuf, NVRAM_WRITE_IN_WRITE_BUFFER), buffer, length);

	BUILD_BUG_ON(MC_CMD_NVRAM_WRITE_OUT_LEN != 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_NVRAM_WRITE, inbuf, inlen, NULL, 0, NULL);
	kfree(inbuf);

	return rc;
}

int efx_mcdi_nvram_erase(struct efx_nic *efx, unsigned int type,
			 loff_t offset, size_t length)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_NVRAM_ERASE_IN_LEN);
	int rc;

	MCDI_SET_DWORD(inbuf, NVRAM_ERASE_IN_TYPE, type);
	MCDI_SET_DWORD(inbuf, NVRAM_ERASE_IN_OFFSET, offset);
	MCDI_SET_DWORD(inbuf, NVRAM_ERASE_IN_LENGTH, length);

	BUILD_BUG_ON(MC_CMD_NVRAM_ERASE_OUT_LEN != 0);

	rc = efx_mcdi_rpc(efx, MC_CMD_NVRAM_ERASE, inbuf, sizeof(inbuf),
			  NULL, 0, NULL);
	return rc;
}

int efx_mcdi_nvram_update_finish(struct efx_nic *efx, unsigned int type,
				 enum efx_update_finish_mode mode)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_NVRAM_UPDATE_FINISH_V2_IN_LEN);
	MCDI_DECLARE_BUF(outbuf, MC_CMD_NVRAM_UPDATE_FINISH_V2_OUT_LEN);
	size_t outlen;
	u32 reboot;
	int rc, rc2;

	/* Reboot PHY's into the new firmware. mcfw reboot is handled
	 * explicity via ethtool. */
	reboot = (type == MC_CMD_NVRAM_TYPE_PHY_PORT0 ||
		  type == MC_CMD_NVRAM_TYPE_PHY_PORT1 ||
		  type == MC_CMD_NVRAM_TYPE_DISABLED_CALLISTO);
	MCDI_SET_DWORD(inbuf, NVRAM_UPDATE_FINISH_IN_TYPE, type);
	MCDI_SET_DWORD(inbuf, NVRAM_UPDATE_FINISH_IN_REBOOT, reboot);

	/* Old firmware doesn't support background update finish and abort
	 * operations. Fallback to waiting if the requested mode is not
	 * supported.
	 */
	if (!efx_has_cap(efx, NVRAM_UPDATE_POLL_VERIFY_RESULT) ||
	    (!efx_has_cap(efx, NVRAM_UPDATE_ABORT_SUPPORTED) &&
	     mode == EFX_UPDATE_FINISH_ABORT))
		mode = EFX_UPDATE_FINISH_WAIT;

	MCDI_POPULATE_DWORD_4(inbuf, NVRAM_UPDATE_FINISH_V2_IN_FLAGS,
			      NVRAM_UPDATE_FINISH_V2_IN_FLAG_REPORT_VERIFY_RESULT,
			      (mode != EFX_UPDATE_FINISH_ABORT),
			      NVRAM_UPDATE_FINISH_V2_IN_FLAG_RUN_IN_BACKGROUND,
			      (mode == EFX_UPDATE_FINISH_BACKGROUND),
			      NVRAM_UPDATE_FINISH_V2_IN_FLAG_POLL_VERIFY_RESULT,
			      (mode == EFX_UPDATE_FINISH_POLL),
			      NVRAM_UPDATE_FINISH_V2_IN_FLAG_ABORT,
			      (mode == EFX_UPDATE_FINISH_ABORT));

	rc = efx_mcdi_rpc(efx, MC_CMD_NVRAM_UPDATE_FINISH, inbuf, sizeof(inbuf),
			  outbuf, sizeof(outbuf), &outlen);
	if (!rc && outlen >= MC_CMD_NVRAM_UPDATE_FINISH_V2_OUT_LEN) {
		rc2 = MCDI_DWORD(outbuf, NVRAM_UPDATE_FINISH_V2_OUT_RESULT_CODE);
		if (rc2 != MC_CMD_NVRAM_VERIFY_RC_SUCCESS &&
		    rc2 != MC_CMD_NVRAM_VERIFY_RC_PENDING)
			netif_err(efx, drv, efx->net_dev,
				  "NVRAM update failed verification with code 0x%x\n",
				  rc2);
		switch (rc2) {
		case MC_CMD_NVRAM_VERIFY_RC_SUCCESS:
			break;
		case MC_CMD_NVRAM_VERIFY_RC_PENDING:
			rc = -EAGAIN;
			break;
		case MC_CMD_NVRAM_VERIFY_RC_CMS_CHECK_FAILED:
		case MC_CMD_NVRAM_VERIFY_RC_MESSAGE_DIGEST_CHECK_FAILED:
		case MC_CMD_NVRAM_VERIFY_RC_SIGNATURE_CHECK_FAILED:
		case MC_CMD_NVRAM_VERIFY_RC_TRUSTED_APPROVERS_CHECK_FAILED:
		case MC_CMD_NVRAM_VERIFY_RC_SIGNATURE_CHAIN_CHECK_FAILED:
			rc = -EIO;
			break;
		case MC_CMD_NVRAM_VERIFY_RC_INVALID_CMS_FORMAT:
		case MC_CMD_NVRAM_VERIFY_RC_BAD_MESSAGE_DIGEST:
			rc = -EINVAL;
			break;
		case MC_CMD_NVRAM_VERIFY_RC_NO_VALID_SIGNATURES:
		case MC_CMD_NVRAM_VERIFY_RC_NO_TRUSTED_APPROVERS:
		case MC_CMD_NVRAM_VERIFY_RC_NO_SIGNATURE_MATCH:
		case MC_CMD_NVRAM_VERIFY_RC_REJECT_TEST_SIGNED:
		case MC_CMD_NVRAM_VERIFY_RC_SECURITY_LEVEL_DOWNGRADE:
			rc = -EPERM;
			break;
		default:
			netif_err(efx, drv, efx->net_dev,
				  "Unknown response to NVRAM_UPDATE_FINISH\n");
			rc = -EIO;
		}
	}
	return rc;
}

#define	EFX_MCDI_NVRAM_UPDATE_FINISH_INITIAL_POLL_DELAY_MS 5
#define	EFX_MCDI_NVRAM_UPDATE_FINISH_MAX_POLL_DELAY_MS 5000
#define	EFX_MCDI_NVRAM_UPDATE_FINISH_RETRIES 185

int efx_mcdi_nvram_update_finish_polled(struct efx_nic *efx, unsigned int type)
{
	unsigned int delay = EFX_MCDI_NVRAM_UPDATE_FINISH_INITIAL_POLL_DELAY_MS;
	unsigned int retry = 0;
	int rc;

	/* NVRAM updates can take a long time (e.g. up to 1 minute for bundle
	 * images). Polling for NVRAM update completion ensures that other MCDI
	 * commands can be issued before the background NVRAM update completes.
	 *
	 * The initial call either completes the update synchronously, or
	 * returns -EAGAIN to indicate processing is continuing. In the latter
	 * case, we poll for at least 900 seconds, at increasing intervals
	 * (5ms, 50ms, 500ms, 5s).
	 */
	rc = efx_mcdi_nvram_update_finish(efx, type, EFX_UPDATE_FINISH_BACKGROUND);
	while (rc == -EAGAIN) {
		if (retry > EFX_MCDI_NVRAM_UPDATE_FINISH_RETRIES)
			return -ETIMEDOUT;
		retry++;

		msleep(delay);
		if (delay < EFX_MCDI_NVRAM_UPDATE_FINISH_MAX_POLL_DELAY_MS)
			delay *= 10;

		rc = efx_mcdi_nvram_update_finish(efx, type, EFX_UPDATE_FINISH_POLL);
	}
	return rc;
}

int efx_mcdi_nvram_metadata(struct efx_nic *efx, unsigned int type,
			    u32 *subtype, u16 version[4], char *desc,
			    size_t descsize)
{
	MCDI_DECLARE_BUF(inbuf, MC_CMD_NVRAM_METADATA_IN_LEN);
	efx_dword_t *outbuf;
	size_t outlen;
	u32 flags;
	int rc;

	outbuf = kzalloc(MC_CMD_NVRAM_METADATA_OUT_LENMAX_MCDI2, GFP_KERNEL);
	if (!outbuf)
		return -ENOMEM;

	MCDI_SET_DWORD(inbuf, NVRAM_METADATA_IN_TYPE, type);

	rc = efx_mcdi_rpc_quiet(efx, MC_CMD_NVRAM_METADATA, inbuf,
				sizeof(inbuf), outbuf,
				MC_CMD_NVRAM_METADATA_OUT_LENMAX_MCDI2,
				&outlen);
	if (rc)
		goto out_free;
	if (outlen < MC_CMD_NVRAM_METADATA_OUT_LENMIN) {
		rc = -EIO;
		goto out_free;
	}

	flags = MCDI_DWORD(outbuf, NVRAM_METADATA_OUT_FLAGS);

	if (desc && descsize > 0) {
		if (flags & BIT(MC_CMD_NVRAM_METADATA_OUT_DESCRIPTION_VALID_LBN)) {
			if (descsize <=
			    MC_CMD_NVRAM_METADATA_OUT_DESCRIPTION_NUM(outlen)) {
				rc = -E2BIG;
				goto out_free;
			}

			strncpy(desc,
				MCDI_PTR(outbuf, NVRAM_METADATA_OUT_DESCRIPTION),
				MC_CMD_NVRAM_METADATA_OUT_DESCRIPTION_NUM(outlen));
			desc[MC_CMD_NVRAM_METADATA_OUT_DESCRIPTION_NUM(outlen)] = '\0';
		} else {
			desc[0] = '\0';
		}
	}

	if (subtype) {
		if (flags & BIT(MC_CMD_NVRAM_METADATA_OUT_SUBTYPE_VALID_LBN))
			*subtype = MCDI_DWORD(outbuf, NVRAM_METADATA_OUT_SUBTYPE);
		else
			*subtype = 0;
	}

	if (version) {
		if (flags & BIT(MC_CMD_NVRAM_METADATA_OUT_VERSION_VALID_LBN)) {
			version[0] = MCDI_WORD(outbuf, NVRAM_METADATA_OUT_VERSION_W);
			version[1] = MCDI_WORD(outbuf, NVRAM_METADATA_OUT_VERSION_X);
			version[2] = MCDI_WORD(outbuf, NVRAM_METADATA_OUT_VERSION_Y);
			version[3] = MCDI_WORD(outbuf, NVRAM_METADATA_OUT_VERSION_Z);
		} else {
			version[0] = 0;
			version[1] = 0;
			version[2] = 0;
			version[3] = 0;
		}
	}

out_free:
	kfree(outbuf);
	return rc;
}

#ifdef CONFIG_SFC_MTD

int efx_mcdi_mtd_read(struct mtd_info *mtd, loff_t start,
		      size_t len, size_t *retlen, u8 *buffer)
{
	struct efx_mtd_partition *part = mtd->priv;
	loff_t offset = start;
	loff_t end = min_t(loff_t, start + len, mtd->size);
	size_t chunk;
	int rc = 0;

	while (offset < end) {
		chunk = min_t(size_t, end - offset, EFX_MCDI_NVRAM_LEN_MAX);
		rc = efx_mcdi_nvram_read(part->mtd_struct->efx,
					 part->nvram_type,
					 offset, buffer, chunk);
		if (rc)
			goto out;
		offset += chunk;
		buffer += chunk;
	}
out:
	*retlen = offset - start;
	return rc;
}

int efx_mcdi_mtd_erase(struct mtd_info *mtd, loff_t start, size_t len)
{
	struct efx_mtd_partition *part = mtd->priv;
	loff_t offset = start & ~((loff_t)(mtd->erasesize - 1));
	loff_t end = min_t(loff_t, start + len, mtd->size);
	struct efx_nic *efx = part->mtd_struct->efx;
	size_t chunk = part->mtd.erasesize;
	int rc = 0;

	if (!part->updating) {
		rc = efx_mcdi_nvram_update_start(efx, part->nvram_type);
		if (rc)
			goto out;
		part->updating = true;
	}

	/* The MCDI interface can in fact do multiple erase blocks at once;
	 * but erasing may be slow, so we make multiple calls here to avoid
	 * tripping the MCDI RPC timeout. */
	while (offset < end) {
		rc = efx_mcdi_nvram_erase(efx, part->nvram_type, offset,
					  chunk);
		if (rc)
			goto out;
		offset += chunk;
	}
out:
	return rc;
}

int efx_mcdi_mtd_write(struct mtd_info *mtd, loff_t start,
		       size_t len, size_t *retlen, const u8 *buffer)
{
	struct efx_mtd_partition *part = mtd->priv;
	struct efx_nic *efx = part->mtd_struct->efx;
	loff_t offset = start;
	loff_t end = min_t(loff_t, start + len, mtd->size);
	size_t chunk;
	int rc = 0;

	if (!part->updating) {
		rc = efx_mcdi_nvram_update_start(efx, part->nvram_type);
		if (rc)
			goto out;
		part->updating = true;
	}

	while (offset < end) {
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_MTD_WRITESIZE)
		chunk = min_t(size_t, end - offset, mtd->writesize);
#else
		chunk = min_t(size_t, end - offset, part->common.writesize);
#endif
		rc = efx_mcdi_nvram_write(efx, part->nvram_type, offset,
					  buffer, chunk);
		if (rc)
			goto out;
		offset += chunk;
		buffer += chunk;
	}
out:
	*retlen = offset - start;
	return rc;
}

int efx_mcdi_mtd_sync(struct mtd_info *mtd)
{
	struct efx_mtd_partition *part = mtd->priv;
	int rc = 0;

	if (part->updating) {
		part->updating = false;
		rc = efx_mcdi_nvram_update_finish(part->mtd_struct->efx,
						  part->nvram_type,
						  EFX_UPDATE_FINISH_WAIT);
	}

	return rc;
}

void efx_mcdi_mtd_rename(struct efx_mtd_partition *part)
{
	struct efx_nic *efx = part->mtd_struct->efx;

	if (!efx)
		return;

	snprintf(part->name, sizeof(part->name), "%s %s:%02x",
		 efx->name, part->type_name, part->fw_subtype);
}

#endif /* CONFIG_SFC_MTD */

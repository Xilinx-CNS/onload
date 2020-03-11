/* SPDX-License-Identifier: LGPL-2.1 */
/* X-SPDX-Copyright-Text: (c) Solarflare Communications Inc */
#include "ef_vi_internal.h"
#include "logging.h"
#include <ci/tools.h>


static inline int64_t timespec_diff_ns(struct timespec a, struct timespec b)
{
  return (a.tv_sec - b.tv_sec) * (int64_t) 1000000000
    + (a.tv_nsec - b.tv_nsec);
}


static unsigned frc_per_n_calls(int iter)
{
  uint32_t start, end;
  int i;
  ci_frc32(&start);
  end = start;
  for( i = 0; i < iter; ++i )
    ci_frc32(&end);
  return end - start;
}


static void measure_frc(uint64_t* tick_rate,
                        unsigned* resolution_ticks,
                        unsigned* resolution_ns)
{
  struct timespec s, e;
  unsigned min_frc = 0, frc;
  int64_t min_ns = 0, ns;
  int first = 1;
  int i, n = 100000;

  for( i = 0; i < 10; ++i ) {
    clock_gettime(CLOCK_MONOTONIC, &s);
    frc = frc_per_n_calls(n);
    clock_gettime(CLOCK_MONOTONIC, &e);
    ns = timespec_diff_ns(e, s);
    if( first || ns < min_ns ) {
      min_frc = frc;
      min_ns = ns;
    }
    first = 0;
  }

  if( tick_rate != NULL )
    *tick_rate = (uint64_t) min_frc * 1000000000 / min_ns;
  if( resolution_ticks != NULL )
    *resolution_ticks = min_frc / n;
  if( resolution_ns != NULL )
    *resolution_ns = min_ns / n;
}


static uint64_t tick_rate;
static unsigned resolution_ns, resolution_ticks;


static void get_tick_rate(void)
{
  if( tick_rate == 0 ) {
    measure_frc(&tick_rate, &resolution_ticks, &resolution_ns);
    LOGAV(ef_log("ef_vi: tick_rate=%"PRIu64" resolution=%dticks %dns",
                 tick_rate, resolution_ticks, resolution_ns));
  }
}


static unsigned Mbps_to_ticks_per_wb(unsigned Mbps)
{
  /* unsigned ns_per_wb = EF_VI_WRITE_BUFFER_SIZE * 8 * 1000 / Mbps;
   * return ns_per_wb * tick_rate / 1000000000;
   */
  return (uint64_t) EF_VI_WRITE_BUFFER_SIZE * 8 * tick_rate / Mbps / 1000000;
}


static unsigned ticks_per_wb_to_Mbps(unsigned ticks_per_wb)
{
  /* unsigned ns_per_wb = (uint64_t) ticks_per_wb * 1000000000 / tick_rate;
   * return EF_VI_WRITE_BUFFER_SIZE * 8 * 1000 / ns_per_wb;
   */
  return (uint64_t) EF_VI_WRITE_BUFFER_SIZE * 8 * tick_rate
    / ticks_per_wb / 1000000;
}


int ef_vi_ctpio_init(ef_vi* vi)
{
  int first_time = (tick_rate == 0);

  get_tick_rate();

  {
    /* We need to write somewhat faster than line rate to avoid underrun in
     * cut-through mode.  We also need to avoid writing too fast, as that
     * encourages TLPs to go out-of-order.
     *
     * TODO: Supporting 10Gbit link only for now.
     */
    unsigned link_Mbps = 10000;
    unsigned max_ticks_for_link_speed = Mbps_to_ticks_per_wb(link_Mbps);
    /* The delay between WB words is believed to be quantized by rdtsc,
     * which has a quite limited throughput.  Therefore the b/w achieved
     * will be lower than implied by the above result.  This adjustment
     * should ensure we at least achieve the link speed:
     */
    max_ticks_for_link_speed -= resolution_ticks;

    {
      unsigned target_Gbps = 20000;
      unsigned ticks_for_target = Mbps_to_ticks_per_wb(target_Gbps);
      unsigned wb_ticks = CI_MIN(ticks_for_target, max_ticks_for_link_speed);
      unsigned min_Mbps = ticks_per_wb_to_Mbps(wb_ticks + resolution_ticks);
      unsigned max_Mbps = ticks_per_wb_to_Mbps(wb_ticks);

      if( first_time ) {
        LOGAV(ef_log("%s: max_ticks_for_link_speed=%u ticks_for_target=%u",
                     __func__, max_ticks_for_link_speed, ticks_for_target));
        LOGAV(ef_log("%s: SETTING: wb_ticks=%u Mbps=%u-%u",
                     __func__, wb_ticks, min_Mbps, max_Mbps));
      }
      vi->vi_ctpio_wb_ticks = wb_ticks;
    }
  }

  {
    const char* s = getenv("EF_VI_CTPIO_WB_TICKS");
    if( s != NULL ) {
      unsigned wb_ticks = atoi(s);
      unsigned min_Mbps = ticks_per_wb_to_Mbps(wb_ticks + resolution_ticks);
      unsigned max_Mbps = ticks_per_wb_to_Mbps(wb_ticks);
      if( first_time )
        LOGAV(ef_log("%s: ENV: wb_ticks=%u Mbps=%u-%u",
                     __func__, wb_ticks, min_Mbps, max_Mbps));
      vi->vi_ctpio_wb_ticks = wb_ticks;
    }
  }

  return 0;
}

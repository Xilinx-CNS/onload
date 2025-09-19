/* SPDX-License-Identifier: BSD-2-Clause */
/* SPDX-FileCopyrightText: (c) Copyright 2025 Advanced Micro Devices, Inc. */

@Library('onload_jenkins_pipeline_lib')

import groovy.transform.Field

import com.solarflarecom.onload.autosmoke.AutosmokeManager
import com.solarflarecom.onload.notifications.NotificationManager
import com.solarflarecom.onload.properties.PropertyManager
import com.solarflarecom.onload.scm.SCMManager

@Field
def autosmoke = new AutosmokeManager(this)

@Field
def nm = new NotificationManager(this)

@Field
def props = new PropertyManager(this)

@Field
def vcm = new SCMManager(this)

void doCommitTestHistoryPipeline() {
  props.commitTestHistoryProperties()

  autosmoke.doCommitTestHistory(vcm.sourceUrl(), vcm.branchName())
}

doCommitTestHistoryPipeline()


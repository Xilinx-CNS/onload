/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: Copyright (C) 2024, Advanced Micro Devices, Inc .*/

@Library('onload_jenkins_pipeline_lib')
import groovy.io.FileType
import groovy.transform.Field

import com.solarflarecom.onload.autosmoke.AutosmokeManager;
import com.solarflarecom.onload.properties.PropertyManager

@Field
def autosmoke = new AutosmokeManager(this)

@Field
def props = new PropertyManager(this)


void doAutosmoke(repo, branch, bookmark, pretend=false) {
  pretend = pretend || env.JOB_NAME.startsWith('personal/')
  autosmoke.doAutosmoke(repo, branch, bookmark, pretend, true)
}

void doPerfBaselinePipeline() {
  props.onloadPipelineProperties()

  def scm_source = autosmoke.sourceUrl()
  /* Performance baseline tests are run on packages defined in the orgfiles
   * for this branch's test plan. Runbench requires us to pass a driver tag
   * here, but it will be ignored in the tests. */
  doAutosmoke(scm_source, env.BRANCH_NAME, "last_known_good/onload-8.1")
}

doPerfBaselinePipeline()

/*
** Local variables:
** groovy-indent-offset: 2
** indent-tabs-mode: nil
** fill-column: 75
** tab-width: 2
** End:
**
** vim: set softtabstop=2 shiftwidth=2 tabstop=2  expandtab:
*/

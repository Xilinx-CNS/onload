import groovy.transform.Field

import com.solarflarecom.onload.autosmoke.AutosmokeManager;
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

void doMatrixReportPipeline() {
  props.matrixReportProperties()

  nm.slack_notify {
    autosmoke.doMatrixReport(vcm.sourceUrl(), vcm.branchName())
    // doPerformanceReport get the test_phase, but that now requires the
    // flavour, which it doesn't know about.  As it is for generating the
    // graphs for the TV which we no longer have, we're putting off
    // figuring out what we want to do with it until it's important
    // again.
    // autosmoke.doPerformanceReport(script.scm.source, script.env.BRANCH_NAME);
  }
}

doMatrixReportPipeline()

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

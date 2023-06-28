/* SPDX-License-Identifier: BSD-2-Clause */
/* X-SPDX-Copyright-Text: (c) Copyright 2019-2020 Xilinx, Inc. */

@Library('onload_jenkins_pipeline_lib')
import groovy.io.FileType
import groovy.transform.Field

import com.solarflarecom.onload.autosmoke.AutosmokeManager;
import com.solarflarecom.onload.notifications.NotificationManager
import com.solarflarecom.onload.properties.PropertyManager
import com.solarflarecom.onload.packaging.OnloadPackaging
import com.solarflarecom.onload.publishing.ArtifactoryPublisher;
import com.solarflarecom.onload.test.TestManager
import com.solarflarecom.onload.utils.UtilityManager

@Field
def nm = new NotificationManager(this)

@Field
def utils = new UtilityManager(this)

@Field
def autosmoke = new AutosmokeManager(this)

@Field
def props = new PropertyManager(this)

@Field
def packager = new OnloadPackaging(this)

@Field
def tm = new TestManager(this)

@Field
def coverage_files = [:]

void doCplanePipeline(List gcovr_options)
{
  String[] gcov_paths = [
    'build/**/*.gc*',
    'build/gnu_x86_64/tests/onload/cplane_unit',
  ]
  coverage_files['cplane'] = tm.runUnitTest('cplane', 'check:unit:cplane', gcov_paths, true, [], gcovr_options)
}

void doOOFPipeline(List gcovr_options)
{
  String[] gcov_paths = [
    'build/**/*.gc*',
    'build/gnu_x86_64/tests/onload/oof/oof_test',
  ]
  coverage_files['oof'] = tm.runUnitTest('oof', 'check:unit:oof', gcov_paths, true, [], gcovr_options)
}

void doORMPipeline(List gcovr_options)
{
  String[] gcov_paths = [
    'build/**/*.gc*',
    'build/gnu_x86_64/tests/onload/onload_remote_monitor/internal_tests/test_ftl',
  ]
  coverage_files['orm'] = tm.runUnitTest('orm', 'check:unit:orm', gcov_paths, true, [], gcovr_options)
}

void doDeveloperBuild(String build_profile=null) {
  def components = ['kernel_driver', 'userspace', 'efct_driver', 'kernel_driver_no_sfc']
  def debugnesses = ['DEBUG', 'NDEBUG']

  def stage_name = 'Developer Build'
  if( build_profile ) {
    stage_name += " (profile: ${build_profile})"
  }
  stage(stage_name) {
    tasks = [:]

    for( def component_i=0; component_i<components.size(); component_i++) {
      def component = components[component_i]
      for( def debugness_i=0; debugness_i<debugnesses.size(); debugness_i++) {
        def debugness = debugnesses[debugness_i]

        def thread_title = "${component}-${debugness}"

        def defines = [:]
        if( debugness == 'NDEBUG' ) {
          defines['NDEBUG'] = '1'
        }
        if( build_profile ) {
          defines['TRANSPORT_CONFIG_OPT_HDR'] = "ci/internal/transport_config_opt_${build_profile}.h"
        }

        tasks[thread_title] = {
          node('dev-build') {
            def workspace = "workspace/${new URLDecoder().decode(env.JOB_NAME)}/exec-${env.EXECUTOR_NUMBER}-${thread_title}" 
            ws(workspace) {
              if( component == 'efct_driver' ) {
                  dir("x3-net") {
                    echo("Checking out x3")
                    x3net = checkout([
                      $class: 'GitSCM',
                      branches: [[name: 'dev']],
                      userRemoteConfigs: [[url: 'ssh://git@github.com/Xilinx-CNS/x3-net-linux.git']]
                    ])
                  }
                  dir("aux-bus"){
                    echo("Checking out Aux")
                    aux = checkout([
                      $class: 'GitSCM',
                      branches: [[name: 'master']],
                      userRemoteConfigs: [[url: 'ssh://git@github.com/Xilinx-CNS/cns-auxiliary-bus.git']]
                    ])
                  }
              }
              checkout scm
              utils.rake(["build:${component}"], defines: defines)
              deleteDir() // Delete the manually allocated workspace
            }
          }
        }
      }
    }

    utils.parallel(tasks)
  }
}

void doUnitTests(List gcovr_options) {
  stage('Unit tests') {
    utils.parallel(
      'cplane': {
        doCplanePipeline(gcovr_options)
      },
      'ftl': {
        doORMPipeline(gcovr_options)
      },
      'oof': {
        doOOFPipeline(gcovr_options)
      },
    )
  }
}

void doSystemTests() {
  stage('System tests') {
    String[] gcov_paths = [
      'build/**/*.gc*',
      'src/tests/onload/cplane_sysunit/*',
      'build/gnu_x86_64/tests/onload/cplane_sysunit',
    ]
    utils.parallel(
      'netlink-inc-bond': {
        withEnv([
          'CPLANE_SYS_ASSERT_NETLINK_BOND=Included'
        ]) {
          coverage_files['cplane-sys-netlink-inc-bond'] = tm.runUnitTest(
            'cplane-sys-netlink-inc-bond',
            'check:cplane_sys',
            gcov_paths,
            true,
            ['netlink-inc-bond'],
          )
        }
      },
    )
  }
}

void doAutosmoke(repo, branch, bookmark, pretend=false) {
  pretend = pretend || env.JOB_NAME.startsWith('personal/')
  autosmoke.doAutosmoke(repo, branch, bookmark, pretend)
}

String[] list_build_profiles() {
  def profiles = []

  dir('src/include') {
    def files = findFiles(glob: 'ci/internal/transport_config_opt_*.h')
    for( int i = 0; i < files.size(); ++i ) {
      def profile_name = files[i].name.replaceFirst(/^transport_config_opt_/, '').replaceFirst(/\.h$/,'')

      /* "extra" is the default profile that has already been built before
       * we ran the unit tests.  "af_xdp" requires a newer kernel that we have
       * available. */
      if( ! ['extra', 'af_xdp'].contains(profile_name) ) {
        profiles.add(profile_name)
      }
    }
  }

  return profiles
}

void doUnitTestsPipeline() {
  props.onloadPipelineProperties()

  def long_revision
  def short_revision
  String product
  String onload_version_long, onload_version_short
  List gcovr_options
  String[] build_profiles

  nm.slack_notify {
    node('unit-test-parallel') {
      stage('Checkout') {
        def scmVars = checkout scm
        long_revision = scmVars.GIT_COMMIT
        short_revision = scmVars.GIT_COMMIT.substring(0,12)
        echo("Got onload revision: ${long_revision}")

        product = autosmoke.productToBuild(env.BRANCH_NAME)
        echo("Building ${product}")
        (onload_version_long, onload_version_short) = autosmoke.onload_version('.', product, long_revision)
        echo("Version(long): ${onload_version_long}")
        echo("Version(short): ${onload_version_short}")

        /* We save the src to support the coverage reports */
        stash(name: 'onload-src', includes: 'src/**/*', useDefaultExcludes: false)

        build_profiles = list_build_profiles()
        echo("Profiles: ${build_profiles}")

        timeout(30) {
          sh 'bundle check || bundle install'
        }
        def gcov = utils.rake(['build:which_gcov'], capture: true)
        gcovr_options = [
          '--gcov-executable', gcov,
        ]
      }
    }

    doDeveloperBuild()
    doUnitTests(gcovr_options)
    doSystemTests()
    tm.publish_coverage_report(coverage_files)

    /* Build for each build profile */
    for( int i = 0; i < build_profiles.size(); ++i ) {
      doDeveloperBuild(build_profiles[i])
    }

    def scm_source = autosmoke.sourceUrl()
    def built_package_locations
    stage('Build packages') {
      /* Use short revision in the version to avoid exceeding length limit. */
      built_package_locations = autosmoke.buildOnloadVersionedPackages(scm_source, product, short_revision, onload_version_short)
    }

    utils.withArtifactoryURL() {
      utils.withArtifactoryCreds() {
        def publisher = new ArtifactoryPublisher(this)
        publisher.publishStashedPackages(product, built_package_locations, autosmoke.onloadBranchName(env.BRANCH_NAME), onload_version_short, long_revision)
      }
    }

    def bookmark = utils.updateLastKnownGoodBookmark(env.BRANCH_NAME, long_revision)

    if( bookmark ) { // Only run autosmoke if the bookmark moved on
      doAutosmoke(scm_source, env.BRANCH_NAME, bookmark)
    } else {
      // ... otherwise just show what those commands would be
      doAutosmoke(scm_source, env.BRANCH_NAME, long_revision, true)
    }
  }
}

doUnitTestsPipeline()

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

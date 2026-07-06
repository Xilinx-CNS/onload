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
import com.solarflarecom.onload.scm.SCMManager

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
def scmmanager = new SCMManager(this)

@Field
final String PROFILE_PREFIX = 'transport_config_opt_'

/**
 * Generate all developer build tasks for a given profile (or default).
 * Returns a Map of task-name -> closure suitable for parallel execution.
 * Uses CPS-safe for-loops (closures in collectEntries don't survive serialization).
 */
Map generateBuildTasks(String build_profile=null) {
  def components = ['kernel_driver', 'userspace', 'efct_driver', 'kernel_driver_no_sfc']
  def debugnesses = ['DEBUG', 'NDEBUG']
  def profile_label = build_profile ?: 'default'
  def tasks = [:]

  for (int i = 0; i < components.size(); i++) {
    for (int j = 0; j < debugnesses.size(); j++) {
      def component = components[i]
      def debugness = debugnesses[j]
      def thread_title = "${profile_label}/${component}-${debugness}"
      def defines = [:]
      if (debugness == 'NDEBUG') {
        defines['NDEBUG'] = '1'
      }
      if (build_profile) {
        defines['TRANSPORT_CONFIG_OPT_HDR'] = "ci/internal/${PROFILE_PREFIX}${build_profile}.h"
      }

      tasks[thread_title] = {
        node('unit-test-master') {
          ws("workspace/${env.JOB_NAME}/${env.BUILD_NUMBER}/${thread_title}") {
            if (component == 'efct_driver') {
              dir("x3-net") {
                scmmanager.cloneGit([branch: 'dev'], 'ssh://git@github.com/Xilinx-CNS/x3-net-linux.git')
              }
            }
            unstash('onload-full')
            def cmd = ["./scripts/build-component", component]
            cmd += defines.collect { k, v -> "${k}=${v}" }
            sh(script: cmd.join(' '))
            deleteDir()
          }
        }
      }
    }
  }
  return tasks
}

Closure testTask(String path, String sub_dir, String target) {
  def test_dir = "build/gnu_x86_64/tests/onload"
  return {
    sh(script: "${path} make -C ${test_dir}/${sub_dir} all && ${path} make -C ${test_dir}/${sub_dir} ${target}")
  }
}

void doTests() {
  node("unit-test-master") {
    ws("workspace/${env.JOB_NAME}/${env.BUILD_NUMBER}/unit_tests") {
      def path = "PATH=\"\$PATH:\$PWD/scripts\""
      stage("Prepare test build") {
        unstash('onload-full')
        sh(script: "scripts/onload_build --strict --debug --user --build-profile=cloud")
      }
      stage("Run Tests") {
        utils.parallel([
          "cplane unit":   testTask(path, 'cplane_unit', 'test'),
          "OOF unit":      testTask(path, 'oof', 'tests'),
          "ORM unit":      testTask(path, 'onload_remote_monitor/internal_tests', 'test'),
          "cplane system": testTask(path, 'cplane_sysunit', 'test')
        ])
      }
    }
  }
}

void doAutosmoke(repo, branch, bookmark, pretend=false) {
  pretend = pretend || env.JOB_NAME.startsWith('personal/')
  autosmoke.doAutosmoke(repo, branch, bookmark, pretend)
}

String[] list_build_profiles() {
  def excluded = ['af_xdp', 'localcrc'] as Set
  def profiles = [null]
  dir('src/include') {
    def files = findFiles(glob: "ci/internal/${PROFILE_PREFIX}*.h")
    for (int i = 0; i < files.size(); i++) {
      def name = files[i].name.replaceFirst(/^${PROFILE_PREFIX}/, '').replaceFirst(/\.h$/, '')
      if (excluded.contains(name)) {
        continue
      }
      if (name == 'ulhelper' && env.BRANCH_NAME != 'master') {
        continue
      }
      profiles.add(name)
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
    node('unit-test-onload9') {
      stage('Checkout') {
        def scmVars = scmmanager.cloneGit(scm)
        long_revision = scmVars.GIT_COMMIT
        short_revision = scmVars.GIT_COMMIT.substring(0,12)
        echo("Got onload revision: ${long_revision}")

        product = autosmoke.productToBuild(env.BRANCH_NAME)
        echo("Building ${product}")
        (onload_version_long, onload_version_short) = autosmoke.onload_version('.', product, long_revision)
        echo("Version(long): ${onload_version_long}")
        echo("Version(short): ${onload_version_short}")

        sh 'echo "File count before stash:" && find . -not -path "./.git/*" -type f | wc -l && du -sh --exclude=.git . && find . -maxdepth 1 -type d | sort'

        /* Stash only source tree needed for builds (excludes leftover workspace dirs) */
        stash(name: 'onload-full', includes: 'src/**,scripts/**,mk/**,Makefile,imports.mk,versions.env,pyproject.toml')
        /* Src-only stash for coverage reports */
        stash(name: 'onload-src', includes: 'src/**/*', useDefaultExcludes: false)

        build_profiles = list_build_profiles()
        echo("Profiles: ${build_profiles}")

        def gcov = sh(script: './scripts/which-gcov', returnStdout: true).trim()
        gcovr_options = [
          '--gcov-executable', gcov,
        ]
      }
    }

    /* All builds are independent — run them in a single flat parallel block. */
    def all_tasks = [:]
    for (int i = 0; i < build_profiles.size(); i++) {
      all_tasks += generateBuildTasks(build_profiles[i])
    }
    all_tasks['Unit Tests'] = { doTests() }
    utils.parallel(all_tasks)

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

# SPDX-License-Identifier: GPL-2.0
# X-SPDX-Copyright-Text: (c) Copyright 2013-2019 Xilinx, Inc.

import sys, re


class Stream(object):
    def __init__(self):
        self.capturestream = []
        self.capturemode = None
        self.promiscuous = None

    def set(self, attr, val):
        if attr == 'capturestream':
            self.capturestream.append(val.replace(' ', ''))
            return
        if attr not in ['capturemode', 'promiscuous']:
            raise SyntaxError("Invalid stream property '%s'" % attr)
        if attr == 'capturemode':
            if self.capturemode:
                raise SyntaxError("Stream property '%s' already set" % attr)
            self.capturemode = val
        elif attr == 'promiscuous':
            if self.promiscuous:
                raise SyntaxError("Stream property '%s' already set" % attr)
            self.promiscuous = int(val)


    def sanitize(self):
        if self.capturemode is not None and \
                self.capturemode not in ['sniff', 'steal']:
            raise SyntaxError("CaptureMode can only be 'sniff' or 'steal' not "
                              "'%s'." % self.capturemode)
        if self.promiscuous is not None and self.promiscuous not in [0, 1]:
            raise SyntaxError("Promiscuous can only be '0' or '1' not '%d'" %
                              self.promiscuous)
        if self.capturemode == 'sniff':
            if self.capturestream != ['all']:
                raise SyntaxError("Sniff mode can only be set on 'all' stream")
            if self.promiscuous is None:
                self.promiscuous = 1
            self.capturestream = ['sniff %d' % self.promiscuous]
        if self.capturestream == []:
                raise SyntaxError("No capture streams found")


class Config(object):
    def __init__(self, filename):
        assert filename
        self.__parse_text(open(filename).read())
        self.process_clusters()


    def __str__(self):
        text = ''
        for name, cluster in self.clusters.items():
            text += 'Cluster %s:\n' % (name,)
            for k, v in cluster.items():
                text += '  %s: %s\n' % (k, v)
        return text


    def __parse_text(self, text):
        ''' Builds self.properties.  A dictionary mapping cluster
        names to properites in string format '''
        self.properties = {}
        lines = text.split('\n')

        # Discard comments: bits after ';'
        lines = [l.split(';', 1)[0].strip() for l in lines]
        lines = [l for l in lines if l != '']

        # Join lines ending with '\'
        for i in range(len(lines)):
            if lines[i].endswith('\\'):
                if i == len(lines) - 1:
                    raise SyntaxError("Invalid line: '%s'" % lines[i])
                lines[i] = lines[i].rstrip('\\') + lines[i + 1]
                lines[i + 1] = ''
        lines = [l for l in lines if l != '']

        # Process properties
        property = []
        for line in lines:
            match = re.match(r'\[cluster\s+(\w+)\]', line, flags=re.IGNORECASE)
            if match:
                if property:
                    if name in self.properties.keys():
                        raise SyntaxError("Cluster '%s' specified twice" %
                                          name)
                    self.properties[name] = property
                name = match.group(1)
                property = []
                continue
            if '=' not in line:
                raise SyntaxError("Invalid line: '%s'" % line)
            property.append(line)
        if name in self.properties.keys():
            raise SyntaxError("Cluster '%s' specified twice" % name)
        self.properties[name] = property


    def process_clusters(self):
        ''' Processes self.properties to build self.clusters.  A
        dictionary mapping cluster names to properites in required
        format. '''

        # Required properties that can have only one value
        singleval_props = {
            'captureinterface': str
            }

        # Optional properties that can have only one value and have
        # defaults
        optional_props = {
            'numchannels'    : (int, 1),
            'protectionmode' : (str, 'EF_PD_DEFAULT'),
            }

        self.clusters = {}
        for (cluster_name, props) in self.properties.items():
            self.clusters[cluster_name] = {}
            cluster = self.clusters[cluster_name]

            for k, (_, val) in optional_props.items():
                cluster[k] = val

            streams = {-1: Stream()}
            for prop in props:
                key, val = prop.split('=', 1)
                key = key.lower().strip()
                val = val.strip()
                if key in singleval_props.keys():
                    cluster[key] = singleval_props[key](val)
                    continue
                if key in optional_props.keys():
                    (type, _) = optional_props[key]
                    cluster[key] = type(val)
                    continue

                # Each stream is numbered.  Below, we generate streams
                # dictionary which maps a numbered stream to a Stream
                # class.  If a stream does not have a number, it is
                # assigned -1.

                match = re.match(r'(\w+)\s+(\d+)', key)
                if match:
                    try:
                        streams[int(match.group(2))]
                    except KeyError:
                        streams[int(match.group(2))] = Stream()
                    streams[int(match.group(2))].set(match.group(1), val)
                else:
                    streams[-1].set(key, val)
            for s in streams.values():
                s.sanitize()
            cluster['streams'] = streams

        for (name, props) in self.clusters.items():
            for prop in singleval_props.keys():
                if prop not in props:
                    raise SyntaxError("Cluster '%s' is missing property '%s'" %
                                      (name, prop))

/*
Copyright 2016 BitTorrent Inc

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import os
import sys
import getopt

def parse_file(file,  plot_period):
	inf = open(file, 'r')

	graphs = {}
	time = []
	data = {}
	current = 0

	packets_in = 0
	packets_out = 1

	inout = [{'total': 0}, {'total': 0}, {'total': 0}, {'total': 0}]

	total_data = 0

	tids = { }
	events = { }

	with open(file, 'r') as inf:
		for l in inf:
			# skip lines that are not instrumentation
			loc = l.find('DHTI')
			if loc == -1: continue
			l = l[loc+4:]
			#print l

			fields = l.split('\t')
			if l[0] == '<': direction = packets_in;
			elif l[0] == '>': direction = packets_out;
			elif l[0] == '!':
				event = l[1:].strip()
				if event in events:
					events[event] += 1
				else:
					events[event] = 1
				continue
			else: raise 'invalid direction'

			t = int(fields[1])
			method = fields[2]
			query = fields[3]
			size = int(fields[4])
			tid = fields[5]

			if direction == packets_out:
				tids[tid] = method
			
			if direction == packets_in:
				if method == 'unknown':
					if tid in tids:
						method = tids[tid]
						del tids[tid]

			total_data += size
			inout[direction]['total'] += size
			inout[direction+2]['total'] += 1

			if not method in inout[direction]:
				inout[direction][method] = size
				inout[direction+2][method] = 1
			else:
				inout[direction][method] += size
				inout[direction+2][method] += 1

			if plot_period > 0:
				if not method in graphs:
					graphs[method] = [ [0] * len(time), [0] * len(time) ]
					data[method] = [0, 0]
				if int(t/float(plot_period) + 0.5) > current:
					for m in graphs:
						graphs[m][0].append(data[m][0])
						graphs[m][1].append(data[m][1])
						data[m][0] = 0
						data[m][1] = 0
					time.append(plot_period*current)
					current = int(t/float(plot_period) + 0.5)
				data[method][direction] += size

	if plot_period == 0:
		print 'total data: ', total_data

		print '\ntotal events ', len(events)
		for e in events.keys():
			print '%d\t%s' % ( events[e], e)

		title = ['data in', 'data out', 'packets in', 'packets out']

		for i in range(len(title)):
			print '\n   === %s ===\n' % title[i]

			data = inout[i]
			for d in data:
				print '%s: %d %.2f %%' % (d, data[d], data[d] * 100 / float(data['total']))
	else:
		import matplotlib.pyplot as plt
		plt.figure(1)
		for m in graphs:
			plt.plot(time, graphs[m][0], label=m)
		plt.title('incoming')
		plt.legend()
		plt.xlabel('ms')
		plt.ylabel('bytes')
		plt.figure(2)
		for m in graphs:
			plt.plot(time, graphs[m][1], label=m)
		plt.title('outgoing')
		plt.legend()
		plt.xlabel('ms')
		plt.ylabel('bytes')
		plt.show()

def usage():
	print 'usage', sys.argv[0], '-i input_file [-p plot_sampling_period]'
	print 'print data stats or plot graphs if plot_sampling_period is specified'
	sys.exit(-1)
	
if __name__ == '__main__':
	infile = ''
	plot_period = 0
	try:
		opts, args = getopt.getopt(sys.argv[1:], "i:p:")
	except getopt.GetoptError as err:
		print str(err)
		usage()
	
	for o, a in opts:
		if o == '-i':
			infile = a
		elif o == '-p':
			plot_period = int(a)

	if len(infile) == 0:
		print 'no infile specified'
		usage();
	
	parse_file(infile, plot_period)


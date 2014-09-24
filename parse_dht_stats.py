import os
import sys

inf = open(sys.argv[1], 'r')

packets_in = 0
packets_out = 1

inout = [{'total': 0}, {'total': 0}, {'total': 0}, {'total': 0}]

total_data = 0

for l in inf:
	fields = l.split('\t')
	if l[0] == '<': direction = packets_in;
	elif l[0] == '>': direction = packets_out;
	else: raise 'invalid direction'

	t = l[1]
	method = l[2]
	size = l[3]

	total_data += size
	inout[direction]['total'] += size
	inout[direction+2]['total'] += 1

	if not method in inout[direction]:
		inout[direction][method] = size
		inout[direction+2][method] = 1
	else:
		inout[direction][method] += size
		inout[direction+2][method] += 1

inf.close()

print 'total data: ', total_data

print '\ninput'

title = ['data in', 'data out', 'packets in', 'packets out']

for i in range(title):
	print title[i]

	data = inout[i]
	for d in data:
		print '%s: %f', d, data[d] / data['total']


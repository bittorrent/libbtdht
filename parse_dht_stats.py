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

	t = int(fields[1])
	method = fields[2]
	query = fields[3]
	size = int(fields[4])

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

title = ['data in', 'data out', 'packets in', 'packets out']

for i in range(len(title)):
	print '\n   === %s ===\n' % title[i]

	data = inout[i]
	for d in data:
		print '%s: %.2f %%' % (d, data[d] * 100 / float(data['total']))


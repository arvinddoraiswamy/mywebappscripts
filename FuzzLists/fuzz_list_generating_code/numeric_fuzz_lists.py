import random
import sys

#Generate  a random large integer
print random.randrange(0,100000000000000000000000000000)

#Generate a random large float with and without a random large decimal
print random.uniform(0.0,39873285793487643.29357)
print random.uniform(0.0,39873285793487643.2935743967439860376894768945)

#Generate a large negative integer
print random.randrange(-1,-324235436436346353543646,-1)

#Generate a large negative float
print random.uniform(-1.0,-39873285793487643.274809)

#Generate a random hexadecimal number
lst=[random.choice('0123456789abcdef') for i in xrange(30)]
x=''.join(lst)
x='0x'+x
print x

#Largest Python integer
print sys.maxint
print sys.maxint+1

#Smallest Python integer
print -sys.maxsize-2

#Largest Python Float
print sys.float_info.max
print sys.float_info.max+1

#Integer rep of float in memory (This one's by Max)
print int('0'+'1'*8+'0'*23,2)

#Smallest Python float
print sys.float_info.min

#Explicit 'L' and explicit 'B' tagged on at the end
print '79228162514264337593543950336L'
print '79228162514264337593543950336l'
print '79228162514264337593543950336B'

#Different types of infinity :)
print float('inf')
print 'Infinity'
print '-Infinity'

#Not a number
print 'NaN'

#Largest unsigned integers - 8,16,32 and 64 bit
print '255\n65535\n4294967295\n18446744073709551615\n'

#Largest unsigned integers - 8,16,32 and 64 bit PLUS 1
print '256\n65536\n4294967296\n18446744073709551616\n'

#Largest signed integers - 8,16,32 and 64 bit
print '127\n32767\n2147483647\n9223372036854775807\n'

#Largest signed integers - 8,16,32 and 64 bit PLUS 1
print '128\n32768\n2147483648\n9223372036854775808\n'

#Smallest signed integers - 8,16,32 and 64 bit
print '-128\n-32768\n-2147483648\n-9223372036854775808\n'

#Smallest signed integers - 8,16,32 and 64 bit PLUS 1
print '-129\n-32769\n-2147483649\n-9223372036854775809\n'

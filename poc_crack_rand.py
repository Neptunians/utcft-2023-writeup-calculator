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

quit()

# final_state = (first, tuple(new_state), last)
first_state = list(first_state)
current_state = list(current_state)
reversed_state = new_state

print('\n'*5)
print([(x, y) for x,y in zip(reversed_state, first_state)])
print('\n'*5)
print([(x == y) for x,y in zip(reversed_state, first_state)])
print('\n'*5)

print(reversed_state == first_state)
print(len(current_state))

print(f'{reversed_state[0]:b} == {reversed_state[0]}')
print(f'{first_state[0]:b} == {first_state[0]}')

# Last results xor 184829356


# print(i)

# print('\n'*5)
# print(first_state)
# print('\n'*5)
# print(last_state)
# print('\n'*5)



quit()

# for (int i = 623; i >= 0; i--) {
#   int result = 0;
#   // first we calculate the first bit
#   int tmp = state[i];
#   tmp ^= state[(i + 397) % 624];
#   // if the first bit is odd, unapply magic
#   if ((tmp & 0x80000000) == 0x80000000) {
#     tmp ^= 0x9908b0df;
#   }
#   // the second bit of tmp is the first bit of the result
#   result = (tmp << 1) & 0x80000000;

#   // work out the remaining 31 bits
#   tmp = state[(i - 1 + 624) % 624];
#   tmp ^= state[(i + 396) % 624];
#   if ((tmp & 0x80000000) == 0x80000000) {
#     tmp ^= 0x9908b0df;
#     // since it was odd, the last bit must have been 1
#     result |= 1;
#   }
#   // extract the final 30 bits
#   result |= (tmp << 1) & 0x7fffffff;
#   state[i] = result;
# }

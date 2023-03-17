#!/home/neptunian/ctf/venv-ctf/bin/python
import random
import socket

def str_to_state(state_str):
    return eval(state_str, {})

# https://jazzy.id.au/2010/09/25/cracking_random_number_generators_part_4.html
def get_last_state(current_state):
    new_state = list(current_state)
    new_state[-1] = 624 # Sometimes 1

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

    # print(last_state)
    # print(f'{[x==y for x,y in zip(last_state, current_state)]}')

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
        remote_random_state += str(data)

        if remote_random_state.find('), None)') >= 0:
            remote_random_state = remote_random_state.strip()
            reverse_random_state(remote_random_state)
            answer = str(random.getrandbits(32))
            print(f'Answer: {answer}')
            conn.send(bytes(answer, 'UTF-8'))  # send data to the client
            conn.close()  # close the connection
            break

    server_socket.close()

if __name__ == '__main__':
    server_program()
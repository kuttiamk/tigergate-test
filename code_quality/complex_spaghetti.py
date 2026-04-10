import sys
import hashlib
import random

# Code Smell: Usage of Weak Cryptography
def weak_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

# Code Smell: Extremely high cyclomatic complexity and deep nesting
def process_data(data):
    if data:
        for i in range(len(data)):
            if type(data[i]) == dict:
                for k, v in data[i].items():
                    if k == 'important':
                        if v == True:
                            while True:
                                if random.randint(0, 10) > 5:
                                    print("Processing")
                                    if True:
                                        if False:
                                            # Code Smell: Dead Code
                                            print("Unreachable")
                                    break
                                else:
                                    continue
    # Code Smell: Return inside main function without properly handling structure
    return True

# Code Smell: Insecure randomness and bad variable names
def doSomething():
    a = random.random()
    b = a * 10
    c = b + 1
    # print(c) - Commented out code block
    return c


counter = 0

def thread1():
    global counter
    while counter != 100000:
        counter += 1
    return counter  

def thread2():
    global counter
    while counter != 0:
        counter -= 1
    return counter  


thread1()
result = thread2()

print(result)  
import random
height = 100
width = 120
output = ""
for i in range(height):
    
    for j in range(width):
        x = random.randint(0,255)
        output = output + str(x) + " "
    output = output + "\n"
with open("fake_image.txt", "w") as file:
    file.write(output)

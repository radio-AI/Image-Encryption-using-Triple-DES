pi=100005

salt_const=b"$ez*}-d3](%d%$#*!)$#%s45le$*fhucdivyanshu75456dgfdrrrrfgfs^"

#importing libraries
from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from getpass import getpass
from Crypto.Protocol.KDF import PBKDF2
from cryptography.fernet import Fernet
from tkinter import *
import socket
from tkinter import messagebox
import os
import time


#encrypting function
def encryptor(path):
	#opening the image file
	try:
		with open(path, 'rb') as imagefile:
			image=imagefile.read()
			
			
		#padding	
		while len(image)%8!=0:
			image+=b" "
	except:
		print("Error loading the file, make sure file is in same directory, spelled correctly and non-corrupted")
		exit()
	
	 
	#hashing original image in SHA256	
	hash_of_original=SHA256.new(data=image)
	global ciphertext3

	with open("Avinash21.jpg", 'rb') as image_file1:
		image1 = image_file1.read()
	while len(image1)%8!=0:
		image1+=b" "  
	
        
	
	#Inputting Keys
	key_enc=getpass(prompt="Enter minimum 8 character long password:")
	#Checking if key is of invalid length
	while len(key_enc)<8:
		key_enc=getpass(prompt="Invalid password! Enter atleast 8 character password:")
	
	key_enc_confirm=getpass(prompt="Enter password again:")
	while key_enc!=key_enc_confirm:
		print("Key Mismatch.Try again.")
		key_enc=getpass(prompt="Enter 8 character long password:")
	
		#Checking if key is of invalid length
		while len(key_enc)<8:
			key_enc=getpass(prompt="Invalid password! Enter atleast 8 character password:")
		key_enc_confirm=getpass(prompt="Enter password again:")
	
	
	#Salting and hashing password
	key_enc=PBKDF2(key_enc,salt_const,48,count=pi)

	
	#Encrypting using triple 3 key DES	
	print("Encrypting...")	
	try:
		
		cipher1=DES.new(key_enc[0:8],DES.MODE_CBC,key_enc[24:32])
		ciphertext1=cipher1.encrypt(image)
		cipher2=DES.new(key_enc[8:16],DES.MODE_CBC,key_enc[32:40])
		ciphertext2=cipher2.decrypt(ciphertext1)
		cipher3=DES.new(key_enc[16:24],DES.MODE_CBC,key_enc[40:48])
		ciphertext3=cipher3.encrypt(ciphertext2)
		print("!!!ENCRYPTION SUCCESSFUL!!!")
	except:
		print("Encryption failed...Possible causes:Library not installed properly/low device memory/Incorrect padding or conversions")
		exit()
		
		
	cipher1=DES.new(key_enc[0:8],DES.MODE_CBC,key_enc[24:32])
	ciphertext1=cipher1.encrypt(image1)
	cipher2=DES.new(key_enc[8:16],DES.MODE_CBC,key_enc[32:40])
	ciphertext2=cipher2.decrypt(ciphertext1)
	cipher3=DES.new(key_enc[16:24],DES.MODE_CBC,key_enc[40:48])
	Ciphertext3=cipher3.encrypt(ciphertext2)
	
	#Adding hash at end of encrypted bytes
	ciphertext3=Ciphertext3+hash_of_original.digest()
	print(ciphertext3)
	print(len(ciphertext3))
	global x
	x=str(len(ciphertext3)).encode('utf-8')

    #Saving the file encrypted
	try:
		dpath="encrypted_"+path
		with open(dpath, 'wb') as image_file:
    			image_file.write(ciphertext3)
		print("Encrypted Image Saved successfully as filename "+dpath)
    		
		
	except:
		temp_path=input("Saving file failed!. Enter alternate name without format to save the encrypted file. If it is still failing then check system memory")
		try:
			dpath=temp_path+path
			dpath="encrypted_"+path
			with open(dpath, 'wb') as image_file:
    				image_file.write(ciphertext3)
			print("Encrypted Image Saved successfully as filename "+dpath)
			exit()
		except:
			print("Failed....Exiting...")
			exit()


def send_image():
    global image_name
    s.sendall(ciphertext3)
    posts.destroy()

def Image_transfer():
    global posts
    global image_name
    image_name = StringVar()
    posts = Toplevel(root)
    posts.geometry('600x600')
    Label(posts, text="Enter the Image name : ").place(x=40, y=50)
    Entry(posts, textvariable=image_name).place(x=250, y=50)
    Button(posts, text='Send', command=send_image, fg="green").place(x=300, y=150)
    posts.bind('<Return>', lambda event=None: send_image())
    posts.mainloop()

def displays_conn():
    global x
    connec.destroy()
    print("IP address : ", ip_add.get(), "\nPort Number :", port_num.get())
    global s
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = ip_add.get()
    port = port_num.get()
    s.connect((host, port))  # here we just connect the server
    messagebox.showinfo('Status', "Connection Established")
    s.send(x)


def connects():
    global connec
    global ip_add
    global port_num
    connec = Toplevel(root)
    connec.geometry('600x600')

    ip_add = StringVar()
    port_num = IntVar()

    Label(connec, text='Enter IP address : ').place(x=40, y=50)
    Entry(connec, textvariable=ip_add).place(x=250, y=50)

    Label(connec, text='Enter Port Number : ').place(x=40, y=150)
    Entry(connec, textvariable=port_num).place(x=250, y=150)

    Button(connec, text='Connect', command=displays_conn).place(x=400, y=100)
    connec.bind('<Return>', lambda event=None: displays_conn())
    connec.mainloop()


def disconnects():
    s.send(str.encode("Disconnect"))
    s.close()
    print('Disconnected to server...')
    root.destroy()


# menu ..................................................................................

def adjustWindow(window):
    w = 600  # width for the window size
    h = 600  # height for the window size
    ws = window.winfo_screenwidth()  # width of the screen
    hs = window.winfo_screenheight()  # height of the screen
    x = (ws / 2) - (w / 2)  # calculate x and y coordinates for the Tk window
    y = (hs / 2) - (h / 2)
    window.geometry('%dx%d+%d+%d' % (w, h, x, y))  # set the dimensions of the screen and where it is placed
    window.resizable(False, False)  # disabling the resize option for the window
    # window.configure(background='#174873') # making the background white of the window


# validate the entry data and makes a new entry into the database


def menu():
    global root
    global key
    key = Fernet.generate_key()

    # global s
    root = Tk()
    adjustWindow(root)
    Label(root, text="Encrypted Data Transfer System", width="500", height="2", font=("Calibri", 22, 'bold'), fg='white',
          bg='green').pack()
    Button(root, text='Connect', command=connects, fg="green").place(x=50, y=150)
    Button(root, text='Disconnect', command=disconnects, fg="red").place(x=250, y=150)
    Button(root, text='Image Transfer', command=Image_transfer, fg="blue").place(x=150, y=350)

    root.bind('<Escape>', lambda event=None: root.destroy())
    root.mainloop()


encryptor("Avinash.png")
menu()
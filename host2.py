import socket
from cryptography.fernet import Fernet
pi=100005

salt_const=b"$ez*}-d3](%d%$#*!)$#%s45le$*fhucdivyanshu75456dgfdrrrrfgfs^"

#importing libraries
from Crypto.Cipher import DES
from Crypto.Hash import SHA256
from getpass import getpass
from Crypto.Protocol.KDF import PBKDF2
import time

A = 9998


def create_socket():
	try:
		global host
		global port
		global s
		host = ""
		port = A
		s = socket.socket(socket.AF_INET , socket.SOCK_STREAM)

	except socket.error as e:
		print("socket creation error" + str(e))


def bind_socket():
	try:
		global host
		global port
		global s
		s.bind((host,port))
		print("Binding to the post : "+str(port))
		s.listen(5)

	except socket.error as e:
		print("Socket Binding error "+"\n"+'Retrying ...')
		bind_socket()


def send_command(conn):
		while True:
		#using infinte we can send more than one comman

					if 1==1:
						#index = client_response.index("^")
						#size = int(client_response[5:index])
						#file_name = client_response[index + 1:]
						#print(size)
						global a
						#print(file_name)
						client_response = conn.recv(256456)
						print(client_response)
						f = Fernet(key)
						a = f.decrypt(client_response)
						print(a)
						return a
						'''time.sleep(2)
						decryptor()
						with open("Avinash18", 'rb') as fd:
							fd.write(a)'''




                   
def socket_accept():
	global key
	global a
	global client_response
	conn , address = s.accept()
	print("Connection has been established! \n"+"IP : " + address[0] + " | Port Number : " + str(address[1]))
	size = conn.recv(1024).decode("utf-8")
	time.sleep(2)
	
	client_response = conn.recv(int(size))
	print(client_response)
		#f = Fernet(key)
		#a = f.decrypt(client_response)

			
	
	
	


def decryptor():
	global client_response
	#try:
	#with open("decrypted_Avinash18.png",'rb') as encrypted_file:
			#encrypted_data_with_hash=encrypted_file.read()
	
	#except:
		#print("Unable to read source cipher data. Make sure the file is in same directory...Exiting...")
		#exit()
	
	encrypted_data_with_hash=client_response
	#Inputting the key
	key_dec=getpass(prompt="Enter password:")
	print(key_dec)
	
	
	#extracting hash and cipher data without hash
	extracted_hash=encrypted_data_with_hash[-32:]
	encrypted_data=encrypted_data_with_hash[:-32]

	
	#salting and hashing password
	key_dec=PBKDF2(key_dec,salt_const,48,count=pi)
	print(key_dec)
	

	#decrypting using triple 3 key DES
	print("Decrypting...")
		
	cipher1=DES.new(key_dec[16:24],DES.MODE_CBC,key_dec[40:48])
	plaintext1=cipher1.decrypt(encrypted_data)
	print(plaintext1)
	cipher2=DES.new(key_dec[8:16],DES.MODE_CBC,key_dec[32:40])
	plaintext2=cipher2.encrypt(plaintext1)
	cipher3=DES.new(key_dec[0:8],DES.MODE_CBC,key_dec[24:32])
	plaintext3=cipher3.decrypt(plaintext2)
		
		

	#print("Decryption failed...Possible causes:Library not installed properly/low device memory/Incorrect padding or conversions")
#hashing decrypted plain text
	hash_of_decrypted=SHA256.new(data=plaintext3)

	
	#matching hashes
	if hash_of_decrypted.digest()==extracted_hash:
		print("Password Correct !!!")
		print("DECRYPTION SUCCESSFUL!!!")
	else:
		print("Improper hashing!!!")
		
		
		
		
	#saving the decrypted file	
	try:
		epath="Avinash18.png"
		if epath[:7]=="Avinash":
			epath=epath[7:]
		epath="decrypted_"+epath
		with open(epath, 'wb') as image_file:
			image_file.write(plaintext3)
		print("Image saved successully with name " + epath)
		print("Note: If the decrypted image is appearing to be corrupted then password may be wrong or it may be file format error")
	except:
		temp_path=input("Saving file failed!. Enter alternate name without format to save the decrypted file. If it is still failing then check system memory")
		try:
			epath=temp_path+"encrypted_stores.png"
			with open(epath, 'wb') as image_file:
				image_file.write(plaintext3)
			print("Image saved successully with name " + epath)
			print("Note: If the decrypted image is appearing to be corrupted then password may be wrong or it may be file format error")
		except:
			print("Failed! Exiting...")
			exit()
	

	

#main function
def main():
	create_socket()
	bind_socket()
	socket_accept()

	
    


main()
decryptor()

#!/usr/bin/env python
""" 
  ECIES

  Eliptic curve encryption and decryption tool

    
    Douglas Mejia
"""
from curves import SECP_256k1
from curves import SmallWeierstrassCurveFp
from ecc import string_to_int
from ecc import int_to_string
from curves import BrainPoolP256r1
from ellipticcurve import EllipticCurveFp
from numbertheory import square_root_mod_prime


import hashlib
import aes_siv
import os
import pwd
import click

# def encrypt(file):

# def decrypt(file):
curve = 0
ephem_u= 0
ephem_U =0

def generate_ephem_key_pair():
  '''
  Uses the SECP_256k1 curve size to gerenate an Ephermal private key 
  Ephemeral public key is a point on the curve. 
  Saves the generated keys to a file.

  '''
  curve = SECP_256k1()
  ephem_u = string_to_int(os.urandom(curve.coord_size))
  
  # ephem_U is a point on the curve. Has a x and a y
  ephem_U = ephem_u * curve.generator()

  # store keys
  output = open("keyfiles.txt","w")
  output.write("private key:")
  output.write(str(ephem_u))
  output.write("\n")

  output.write("x:")
  output.write(str(ephem_U.x))
  output.write("\n")

  output.write("y:")
  output.write(str(ephem_U.y))
  output.write("\n")
  output.close();

  encrypt_data(ephem_U,open("test.txt","r"),"encrypt.txt")


def encrypt_data(public_key,file, output):
  """
    encrypts a file using the AES_SIV  an a point on the  generated Elliptic curve
  """
  message = file.read()
  file.close()
  print(message)
  key = hashlib.sha256(int_to_string(public_key.x)).hexdigest()

  cipher = aes_siv.AES_SIV(key)
  ad_list = [ 'ab', 'cd']
  cipher_text = cipher.encrypt( message, ad_list )

  click.echo(cipher_text)

  outputfile = open(output,"w")
  outputfile.write(cipher_text)
  outputfile.close();

  





 

# ---- Command line interface -----------------------------

@click.group()
# @click.option("--tool", help = "produces an encrypted file from given text file ")
def cli():
  pass
  """
    Action:
      encrypt 

    Input file

    Outputfile
  """
  
@cli.command()
@click.argument('input_file', type = click.File('rb'))
@click.argument('output', type = click.File('wb'))
def encrypt(input_file,output):
  generate_ephem_key_pair()
  # encrypt_data(ephem_U,input_file,output)

if __name__ == '__main__':
    cli()





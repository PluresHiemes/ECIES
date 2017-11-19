#!/usr/bin/env python
""" 
  ECIES
  Eliptic curve encryption and decryption tool
  Encrypts a text file to a specific public key 
  Decrypts a specific file a peer public key
  author: Douglas Mejia
  
  following files/libraries provided by Paul Lambert:
    curves
    ecc
    ellipticcurve
    aes_siv
    numbertheory
"""
from curves import SECP_256k1
from curves import SmallWeierstrassCurveFp
from ecc import string_to_int
from ecc import int_to_string
from curves import BrainPoolP256r1
from ellipticcurve import EllipticCurveFp
from numbertheory import square_root_mod_prime
import hashlib
import hmac
import aes_siv
import os
import pwd
import click
import json

def generate_ephem_key_pair(file):
  '''
  Uses the SECP_256k1 curve size to gerenate an Ephermal private key 
  Ephemeral public key is a point on the curve. 
  Saves the generated as elements in a JSON file.
  '''
  curve = SECP_256k1()
  G = curve.generator()
  private = string_to_int( os.urandom(curve.coord_size) )
  public = private * G

  priv_b58 =  int_to_string(private) 
  public_x =  int_to_string(public.x)
  public_y =  int_to_string(public.y)

  data = {
    "Private key": private,
    "X": public.x,
    "Y": public.y
  }

  json.dump(data,file)


def encrypt_data(data,peerKey,ownKey):
  """
    Arguments 
      data: Text from file.
      peerKey: JSON file containing peer public key 
      ownKey: json file Containing own key information
   
    general algorithm for encryption
    u = own private key 
    V = destinations public key 
    secrete Key  = KeyDerivationFunction(u * V)   [in this case HMAC(SHA256( u * V).x) ]


    This funtion will encrypt to a specific public key. 
    encrypts a file using the AES_SIV  an a point on the  generated Elliptic curve

    this function assumes public key exhange has aleady occured.
  """
  curve = SECP_256k1()
  
  #retrieve own and peer key records from json files 
  own_keys = json.load(ownKey)
  peer_keys= json.load(peerKey)

  own_private = own_keys["Private key"]
  peer_public= curve.point(peer_keys["X"],peer_keys["Y"])   
  
  # generate secrete key
  sk =own_private*peer_public
  key = hmac.new( int_to_string(sk.x),"",hashlib.sha256)

  #create cipher text and add own public key to it
  cipher = aes_siv.AES_SIV(key.hexdigest())
  ad_list = ['']
  cipher_text = cipher.encrypt(data, ad_list )
  cipher_text = int_to_string(own_keys["X"])+int_to_string(own_keys["Y"])+ cipher_text
  return cipher_text


def decrypt_data(data,ownKey):
  """
    Arguments 
      data: Text from file.
      ownKey: json file Containing own key information

    Extracts peer public key from text file and uses it to recreate secrete key 
    to decrypt a file. 

    this function assumes public key exhange has aleady occured.
  """
  keys = json.load(ownKey)
  v = keys["Private key"]
  peerPublicX = data[0:32]
  peerPublicY = data[32:64]

  data_no_key = data[64:]

  kx = string_to_int(peerPublicX)
  ky = string_to_int(peerPublicY)

  curve = SECP_256k1()
  peerPublic = curve.point(kx,ky)
  sk = v * peerPublic

  key = hmac.new(int_to_string(sk.x),"",hashlib.sha256)
 
  cipher = aes_siv.AES_SIV(key.hexdigest())
  ad_list = ['']
  cipher_text = cipher.decrypt(data_no_key,[''])
  return cipher_text




@click.group()
# @click.option("--tool", help = "produces an encrypted file from given text file ")
def cli():
  pass
@cli.command()
@click.argument('input', type = click.File('rb'))
@click.argument('output', type = click.File('wb'))
@click.argument('peerkey', type = click.File('rb'))
@click.argument('key', type = click.File('rb'))
def encrypt(input,output,peerkey,key):
  """Encrypts a text file to a public key
  
  parameters: 

  
    Input:file to encrypt.
  
    Outputfile: encrypted file. 
   
  
    peerkey: A json file containing peer key information.
  
    key:  A json file containing own key information.
  """
  data = input.read()
  output.write(encrypt_data(data,peerkey,key))

@cli.command()
@click.argument('input', type = click.File('rb'))
@click.argument('output', type = click.File('wb'))
@click.argument('ownkey', type = click.File('rb'))
def decrypt(input,output,ownkey):
  """Decrypts a text file to a public key
    
    parameters:
    
      input: file to decrypt
    
      output: decrypted results
    
      ownkey: A json file containing own key information
  """
  data = input.read()
  output.write(decrypt_data(data,ownkey))

@cli.command()
@click.argument('output', type = click.File('wb'))
def genKey(output):
  """creates private and public keys using Eliptic Curve
      
      parameters:

        output: where to store generated keys. must be .json 
  """
  generate_ephem_key_pair(output)

if __name__ == '__main__':
    cli()





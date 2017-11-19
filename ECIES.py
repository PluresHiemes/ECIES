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
from ecc_toy import b58encode
from encoding import b85encode,b85decode,base_N_encode,base_N_decode
import hashlib
import hmac
import aes_siv
import os
import pwd
import click
import cPickle as pickle
import json

# def encrypt(file):

# def decrypt(file):
curve = 0
ephem_u= 0
ephem_U =0

def generate_ephem_key_pair(file):
  '''
  Uses the SECP_256k1 curve size to gerenate an Ephermal private key 
  Ephemeral public key is a point on the curve. 
  Saves the generated keys to a file.
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
    Argments 
    data: Text from file.
    key_X: the X coordinate of Bobs(i.e one recieving message) public key (which is a point)
    key_Y: the Y coordinate of Bobs(i.e one recieving message) public key (which is a point)
   
    general algorithm for encryption
    u = own private key 
    V = destinations public key 
    secrete Kkey  = KeyDerivationFunction(u * V)   [in this case HMAC(SHA256( u * V).x) ]



    This funtion will encrypt to a specific public key. 
    encrypts a file using the AES_SIV  an a point on the  generated Elliptic curve
  """
  curve = SECP_256k1()
  own_keys = json.load(ownKey)
  peer_keys= json.load(peerKey)
  own_private = own_keys["Private key"]
  peer_public= curve.point(peer_keys["X"],peer_keys["Y"])   
  
 
  sk = int_to_string(own_private*peerPublic.x)
  key = hmac.new( sk,"",hashlib.sha256)
  cipher = aes_siv.AES_SIV(key.hexdigest())
  ad_list = ['']
  cipher_text = cipher.encrypt(data, ad_list )
  cipher_text = int_to_string(own_keys["X"])+int_to_string(own_keys["Y"])+ cipher_text
  click.echo(cipher_text)
  return cipher_text


def decrypt_data(data,ownKey):

  click.echo(data)
  click.echo()
  click.echo()
  click.echo()

  keys = json.load(ownKey)
  private_key = keys["Private key"]
  peerPublicX = data[0:32]
  peerPublicY = data[32:64]

  data_no_key = data[64:]

  kx = string_to_int(peerPublicX)
  ky = string_to_int(peerPublicY)
  click.echo('private key  {}'.format(private_key))
  click.echo('message x {}'.format(kx))
  click.echo('message y {}'.format(ky))

  curve = SECP_256k1()
  peerPublic = curve.point(kx,ky)
  sk = int_to_string(private_key*peerPublic.x)
  key = hmac.new(sk,"",hashlib.sha256)
  cipher = aes_siv.AES_SIV(key.hexdigest())
  ad_list = ['']
  cipher_text = cipher.decrypt(data_no_key,ad_list )

  click.echo('decrypted data {}'.format(cipher_text))
  return cipher_text

  

import math
__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)


# ---- Command line interface -----------------------------

@click.group()
# @click.option("--tool", help = "produces an encrypted file from given text file ")
def cli():
  pass
  """
    Action:
      encrypt: 
            Input file file to encrypt
            Outputfile: result
            key: public key to encrypt to
  """
  
@cli.command()
@click.argument('input', type = click.File('rb'))
@click.argument('output', type = click.File('wb'))
@click.argument('peerkey', type = click.File('rb'))
@click.argument('key', type = click.File('rb'))
def encrypt(input,output,peerkey,key):
  data = input.read()
  output.write(encrypt_data(data,peerkey,key))

@cli.command()
@click.argument('input', type = click.File('rb'))
@click.argument('output', type = click.File('wb'))
@click.argument('ownkey', type = click.File('rb'))
def decrypt(input,output,ownkey):
  data = input.read()
  output.write(decrypt_data(data,ownkey))

@cli.command()
@click.argument('output', type = click.File('wb'))
def genKey(output):
  generate_ephem_key_pair(output)


if __name__ == '__main__':
    cli()





import requests
import hashlib
import sys

def request_api_data(query_char):
    #get data from pwnedpasswords.com using first 5 characters of SHA1 hashed password
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching - code:{response.status_code}')
    return response

def get_leaks_count(response, hash_to_check):
    #check if your password is contained in data from api
    hashes = (line.split(':') for line in response.text.splitlines())
    for hash, count in hashes:
        if hash == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    #hash your password and split after first 5 characters
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    head, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(head)
    return get_leaks_count(response, tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times')
        else:
            print(f'{password} is secure')

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
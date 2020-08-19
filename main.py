from rsa import RSAInstance, Repository
import random

if __name__ == '__main__':

    # fixing the seed for reproducibility
    random.seed(0)

    # instanciating a public key repository
    repository = Repository()

    # creating two RSA Instances to communicate
    alice = RSAInstance('Alice')
    bob = RSAInstance('Bob')

    # adding public keys to the repository
    for instance in [alice, bob]:
        repository.add_key(instance.name, instance.public_key)

    # taking a look at the repository
    print('=== Public keys repository ===')
    repository.get_all_keys()
    print('======')
    print()

    msg = 'Encrypt it yourself!'
    encrypted = alice.encrypt(msg, bob)
    decryted = bob.decrypt(encrypted, alice)

    print("Original message:", msg)
    print("Encrypted message by Alice:", encrypted)
    print("Decrypted message by Bob:", decryted)

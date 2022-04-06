import random, string, unicodedata, sys, time, threading 

results, valid = {}, [] 

# --------------------------------------------------- #
# Define the functions to use in the implementation #
# --------------------------------------------------- #

def textify(plain):
    ''' Converts the received text to the format needed for execution
    of the algorithm, removing accents, strange characters and symbols. Of the same
    form, we remove spaces and put it in lowercase '''

    plain = unicodedata.normalize("NFKD", plain).encode("ascii","ignore").decode("ascii") # Quitamos las tildes
    text = ''

    for char in plain:
        if char.isalpha(): # quitamos lo que no sean letras
            text += char

    return text.lower() # devolvemos el texto en minúscula

def keygen():
    ''' Generates the key from a temporary alphabet from which they leave
    randomizing characters based on a generated boolean value
    randomly, cases:
        2 True -> 3 characters
        1 True -> 2 characters
        0 True -> 1 character
    (in the latter case, said character is removed from the temp_char to avoid
    that several letters are substituted for the same character)'''
    
    temp_char, key = list(string.ascii_lowercase), []

    for i in range(len(temp_char)):
        i1, i2, i3 = random.sample(range(len(temp_char)-1),3) # tomamos 3 posiciones aleatorias del alfabeto
        if bool(random.getrandbits(1)) and bool(random.getrandbits(1)): # generamos 2 booleanos, si ambos True -> letra = cadena de 3 carácteres
            key.append(temp_char[i1] + temp_char[i3] + temp_char[i2])

        elif bool(random.getrandbits(1)):   # generamos 1 booleano, si True -> letra = cadena de 2 carácteres
            key.append(temp_char[i1] + temp_char[i2])
            
        else:
            key.append(temp_char[i1])   # en caso de que el booleano anterior sea False -> letra = 1 carácter
            temp_char.pop(i1) # Si hay un caracter solo, lo tenemos que sacar para que no haya dos posibles letras con el mismo

    return key # devolvemos la clave

def encrypThor(plain, key):
    ''' Take the plaintext and the given key. Substitute each letter of the
    text by its corresponding number that occupies in the key, initially
    the invalid characters error popped up, but thanks to textify(), it
    could skip the check. Returns the ciphertext '''

    valid_char, cypher = list(string.ascii_lowercase), ''

    for char in plain: 
        if char not in valid_char: # Implementado para versiones anteriores, no llega 
                                   # a tener efecto ya que el texto se preprocesa
            print('\n* Error, \'{}\' no es un carácter válido'.format(char))
            exit()
        else:
            cypher += key[valid_char.index(char)]

    return cypher # devuelve el texto cifrado

def decrypThor(cypher, key):
    ''' Takes the ciphertext and the key. Substitute looking for fragments of the
    text in the key, from highest to lowest, so that if the first 3
    characters do not appear in the key, it will look for the first 2 and last
    the first one alone, then it advances the position counter in the text
    and repeat the cycle. Returns the decrypted text '''

    char_list = list(string.ascii_lowercase)
    plain, cnt = '', 0

    while cnt < len(cypher):
        t1, t2, t3 = cypher[cnt], cypher[cnt+1], cypher[cnt+2] # coje los 3 primeros carácteres 
        if t1+t2+t3 in key: # busca esos caracteres en la clave
            plain += char_list[key.index(t1+t2+t3)]
            cnt+=3
        elif t1+t2 in key: # si no están, toma solo los 2 primeros
            plain += char_list[key.index(t1+t2)]
            cnt+=2
        else: # si tampoco están los dos, toma el único
            plain += char_list[key.index(t1)]
            cnt+=1

    return plain # devuelve el texto plano ya descifrado

def loading():
    ''' Loading animation while keys are being generated '''
    chars = "/—\|" # caracteres usados en la animación
    for char in chars:
        sys.stdout.write('\r'+'Generando claves '+char)
        time.sleep(.1)
        sys.stdout.flush() # recarga la misma linea del terminal para dar la sensación de animación

def tester(plain, gen): # Ruta del texto keygen y número de generaciónes, la coje de main
    ''' Calls the keygen() function the number of times it is passed in
    argument form, then try encrypting and decrypting
    a generic text with the generated keys. The valid ones will be shown
    inside the dictionary results'''

    global results, valid # variables globales para almacenar las claves válidas 

    for i in range(gen): # genera claves y las prueba con los textos de generación
            key = keygen()
            cypher = encrypThor(plain, key)

            try:
                temp = plain == decrypThor(cypher, key) # en caso de que el descifrado sea igual al texto original...
                if temp:
                    results['Key '+str(i)+': '] = key   # ...la clave es asignada como válida y guardada para su uso
                    valid.append(i)
            except:
                pass

def main(plain, gen): # Ruta del texto keygen y número de generaciónes
    ''' Generates the encrypt / decrypt menu, starts
    the process of generating keys (while showing the animation). Then
    displays all valid keys on the screen and asks the user which
    want to use, finally it asks for the plain text document to be encrypted and
    creates a new document with the encrypted text and another document
    with the key, to later use the decryption function '''

    global results, valid

    text = textify(open(plain, 'r', encoding='utf-8').read()) # convertimos el texto a una entrada válida

    opc = int(input('Introduzca el programa que quiera ejecutar (0: codificar, 1: decodificar): '))
    while opc not in (0,1):
        opc = int(input('Solo son válidas las entradas binarias >> (0: codificar, 1: decodificar): '))

    if opc == 0:    # Encriptar

        # Inicia el proceso que llama a la función tester() y muestra la animación
        proceso = threading.Thread(target=tester, args=(text,100,)) # Número de generaciones
        proceso.start()
        while proceso.is_alive(): # mientras tester() esté ejecutando (generación de claves), muestra la animación
            loading()

        # muestra las claves en formato 'bonito'
        print('\n'.join('{}{}'.format(k, v) for k, v in results.items()))
        print('\n')

        key = 999
        while key not in valid: # evitamos que se introduzcan claves no válidas
            key = int(input('Introduzca el número de la clave que desesa usar: '))

        key = results['Key '+str(key)+': ']

        f1 = open('data/'+input('Introduzca el nombre del archivo a cifrar: '), 'r', encoding='utf8') #archivo ejemplo plain.txt, debe estar en la misma carpeta
        cypher = encrypThor(textify(f1.read()), key)

        f2 = open('texto_cifrado.txt', 'w', encoding='utf8')
        f2.write(cypher)

        f3 = open('key.txt', 'w')
        for i in key:
            f3.write(str(i)+',')

        print('\n\nEl texto ha sido cifrado y guardado como ¨texto_cifrado.txt¨, la clave será guardada en ¨key.txt¨\n')

    elif opc == 1:  # Desencriptar
        f1 = open(input('Introduce el nombre del archivo a descifrar: '), 'r', encoding='utf8')
        f2 = open(input('Intruduce el nombre del archivo de la clave: '), 'r', encoding='utf8')
        f3 = open('texto_descifrado.txt', 'w', encoding='utf8')

        f3.write(decrypThor(f1.read(),f2.read().split(',')[:-1]))

        print('\n\nEl texto ha sido descifrado y guardado como ¨texto_descifrado.txt¨\n')



main('data/texto_keygen.txt', 100)
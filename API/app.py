from flask import Flask, request, jsonify, redirect, url_for, render_template
import requests
import hashlib
import sys

app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False


@app.route('/')
def index():
    return render_template("index.html")

@app.route('/passwordpage')
def render_password():
    return render_template("password.html")

@app.route('/emailpage')
def render_email():
    return render_template("email.html")

@app.route('/password',methods=['POST'])
def password():
    # Pega o campo password do form da página HTML
    password= request.form['password']
    # Calcula o sha1 da password
    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # Pega os cinco primeiros caracteres da senha em formato sha1
    sha1_head = sha1pwd[:5]
    # Pega os caracteres restantes da senha em formato sha1
    sha1_tail = sha1pwd[5:]

    # Para a API são passados os 5 primeiros caracteres em sha1
    url = 'https://api.pwnedpasswords.com/range/'+sha1_head
    try:
        r = requests.get(url)

        status_code = r.status_code
        if status_code != 200:
            return jsonify({"Response":"Error","Status":status_code})

        # Pega a resposta e separa o restante dos carateres da contagem
        hashes = (line.split(':') for line in r.text.splitlines())
        #print(list(hashes))
        count = 0
        for hash in list(hashes):
            # Se os caracteres restantes da senha sha1 forem iguais ao elemento de resposta coloque o count associado a esse hash
            if sha1_tail == hash[0]:
                count = hash[1]
        
        return jsonify({"Status":status_code,"Resposta":"Sua senha foi encontrada {} vezes nas bases de dados vazadas.".format(count)})
    
    except requests.exceptions.ConnectTimeout:
        return jsonify({"Error":"Tempo de conexão excedida com: {}".format(url)})
    except requests.exceptions.ConnectionError:
        return jsonify({"Error":"Erro de conexão com: {}".format(url)})
    except requests.exceptions.SSLError:
        return jsonify({"Error":"Erro de conexão SSL com: {}".format(url)})

    return  jsonify({"Senha":password,"Hash":sha1pwd,"Head":sha1_head,"Tail":sha1_tail})

@app.route('/email',methods=['POST'])
def email():
    # Pega o campo email do form da página HTML
    email = request.form['email']
    url = "https://haveibeenpwned.com/api/v2/breachedaccount/"+email
    #url = 'https://api.github.com/events'
    try:
        r = requests.get(url)

        status_code = r.status_code
        if status_code != 200:
            return jsonify({"Response":"Error","Status":status_code})

        #response_data = r.headers['content-type']#list(r.text)
        response_data = r.json()

        #print(response_data.encode('UTF-8'))
        #return jsonify("Status":status_code,"Resposta":"")
        return jsonify({"Response":response_data})
        


    except requests.exceptions.ConnectTimeout:
        return jsonify({"Error":"Tempo de conexão excedida com: {}".format(url)})
    except requests.exceptions.ConnectionError:
        return jsonify({"Error":"Erro de conexão com: {}".format(url)})
    except requests.exceptions.SSLError:
        return jsonify({"Error":"Erro de conexão SSL com: {}".format(url)})

if __name__ == "__main__":
    host = "127.0.0.1"
    port = 8080
    app.run(debug=True, host=host, port=port, use_reloader=True)
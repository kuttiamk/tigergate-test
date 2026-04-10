from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route('/greet')
def greet():
    user_name = request.args.get('name', 'Guest')
    
    # Advanced SAST Vulnerability: Server Side Template Injection (SSTI)
    # Allows Remote Code Execution via payload: {{ self.__init__.__globals__.__builtins__['__import__']('os').popen('id').read() }}
    template = f"<h1>Hello, {user_name}!</h1>"
    
    return render_template_string(template)

if __name__ == '__main__':
    app.run()

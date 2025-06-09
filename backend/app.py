from flask import Flask, request, jsonify
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
import hashlib
import jwt
import datetime
from functools import wraps
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app, origins=['https://biblioteca-api2.vercel.app/'])

# Configuración de la base de datos
DATABASE_CONFIG = {
    'host': os.getenv('PGHOST', 'dpg-d1387a6mcj7s7382rc40-a.oregon-postgres.render.com'),
    'database': os.getenv('PGDATABASE', 'biblioteca_db_rmck'),
    'user': os.getenv('PGUSER', 'biblioteca_db_rmck_user'),
    'password': os.getenv('PGPASSWORD', 'Hdg8tdywlk8IFh1ZTPWq2RnzrIIqlhci'),
    'port': os.getenv('PGPORT', '5432')
}

def get_db_connection():
    """Crear conexión a la base de datos"""
    try:
        conn = psycopg2.connect(**DATABASE_CONFIG)
        return conn
    except psycopg2.Error as e:
        print(f"Error conectando a la base de datos: {e}")
        return None

def init_database():
    """Inicializar base de datos con tablas y datos de ejemplo"""
    conn = get_db_connection()
    if not conn:
        return False
    
    try:
        cur = conn.cursor()
        
        # Crear tabla de usuarios
        cur.execute('''
            CREATE TABLE IF NOT EXISTS usuarios (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(100),
                nombre VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Crear tabla de libros
        cur.execute('''
            CREATE TABLE IF NOT EXISTS libros (
                id SERIAL PRIMARY KEY,
                titulo VARCHAR(200) NOT NULL,
                autor VARCHAR(100) NOT NULL,
                categoria VARCHAR(50) NOT NULL,
                isbn VARCHAR(20) UNIQUE,
                año INTEGER,
                descripcion TEXT,
                estado VARCHAR(20) DEFAULT 'Disponible',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Crear tabla de préstamos
        cur.execute('''
            CREATE TABLE IF NOT EXISTS prestamos (
                id SERIAL PRIMARY KEY,
                libro_id INTEGER REFERENCES libros(id),
                usuario_id INTEGER REFERENCES usuarios(id),
                fecha_prestamo DATE DEFAULT CURRENT_DATE,
                fecha_devolucion DATE,
                estado VARCHAR(20) DEFAULT 'Activo',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Insertar usuario administrador por defecto
        admin_password = generate_password_hash('123456')
        cur.execute('''
            INSERT INTO usuarios (username, password_hash, email, nombre) 
            VALUES (%s, %s, %s, %s) 
            ON CONFLICT (username) DO NOTHING
        ''', ('admin', admin_password, 'admin@biblioteca.com', 'Administrador'))
        
        # Insertar libros de ejemplo
        libros_ejemplo = [
            ('Cien años de soledad', 'Gabriel García Márquez', 'Ficción', '978-0-06-088328-7', 1967, 
             'Una obra maestra del realismo mágico que narra la historia de la familia Buendía.', 'Disponible'),
            ('El Quijote', 'Miguel de Cervantes', 'Ficción', '978-84-376-0494-7', 1605,
             'La historia del ingenioso hidalgo Don Quijote de La Mancha.', 'Prestado'),
            ('Una breve historia del tiempo', 'Stephen Hawking', 'Ciencia', '978-0-553-38016-3', 1988,
             'Explicaciones sobre el universo, el tiempo y la relatividad para el público general.', 'Disponible'),
            ('Sapiens', 'Yuval Noah Harari', 'Historia', '978-0-06-231609-7', 2011,
             'De animales a dioses: Breve historia de la humanidad.', 'Disponible'),
            ('Clean Code', 'Robert C. Martin', 'Tecnología', '978-0-13-235088-4', 2008,
             'Manual de estilo para el desarrollo ágil de software.', 'Prestado'),
            ('El poder del ahora', 'Eckhart Tolle', 'No Ficción', '978-1-57731-152-2', 1997,
             'Una guía hacia la iluminación espiritual.', 'Disponible')
        ]
        
        for libro in libros_ejemplo:
            cur.execute('''
                INSERT INTO libros (titulo, autor, categoria, isbn, año, descripcion, estado) 
                VALUES (%s, %s, %s, %s, %s, %s, %s) 
                ON CONFLICT (isbn) DO NOTHING
            ''', libro)
        
        conn.commit()
        cur.close()
        conn.close()
        print("Base de datos inicializada correctamente")
        return True
        
    except psycopg2.Error as e:
        print(f"Error inicializando base de datos: {e}")
        conn.rollback()
        return False

def token_required(f):
    """Decorador para verificar token JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        
        if not token:
            return jsonify({'error': 'Token faltante'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user_id = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token inválido'}), 401
        
        return f(current_user_id, *args, **kwargs)
    
    return decorated

# RUTAS DE LA API

@app.route('/api/login', methods=['POST'])
def login():
    """Autenticación de usuario"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Usuario y contraseña requeridos'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Error de conexión a la base de datos'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM usuarios WHERE username = %s', (username,))
        user = cur.fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            # Generar token JWT
            token = jwt.encode({
                'user_id': user['id'],
                'username': user['username'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm='HS256')
            
            cur.close()
            conn.close()
            
            return jsonify({
                'success': True,
                'token': token,
                'user': {
                    'id': user['id'],
                    'username': user['username'],
                    'nombre': user['nombre'],
                    'email': user['email']
                }
            })
        else:
            cur.close()
            conn.close()
            return jsonify({'error': 'Credenciales inválidas'}), 401
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/books', methods=['GET'])
@token_required
def get_books(current_user_id):
    """Obtener todos los libros"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Error de conexión a la base de datos'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Parámetros de búsqueda y filtros
        search = request.args.get('search', '')
        category = request.args.get('category', '')
        
        query = '''
            SELECT id, titulo, autor, categoria, isbn, año, descripcion, estado, 
                   created_at, updated_at 
            FROM libros 
            WHERE 1=1
        '''
        params = []
        
        if search:
            query += ' AND (titulo ILIKE %s OR autor ILIKE %s OR categoria ILIKE %s)'
            search_param = f'%{search}%'
            params.extend([search_param, search_param, search_param])
        
        if category:
            query += ' AND categoria = %s'
            params.append(category)
        
        query += ' ORDER BY titulo'
        
        cur.execute(query, params)
        books = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'books': [dict(book) for book in books]
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/books/<int:book_id>', methods=['GET'])
@token_required
def get_book(current_user_id, book_id):
    """Obtener un libro específico"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Error de conexión a la base de datos'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM libros WHERE id = %s', (book_id,))
        book = cur.fetchone()
        
        if not book:
            cur.close()
            conn.close()
            return jsonify({'error': 'Libro no encontrado'}), 404
        
        cur.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'book': dict(book)
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/books/<int:book_id>/borrow', methods=['POST'])
@token_required
def borrow_book(current_user_id, book_id):
    """Prestar un libro"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Error de conexión a la base de datos'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Verificar que el libro existe y está disponible
        cur.execute('SELECT * FROM libros WHERE id = %s', (book_id,))
        book = cur.fetchone()
        
        if not book:
            cur.close()
            conn.close()
            return jsonify({'error': 'Libro no encontrado'}), 404
        
        if book['estado'] != 'Disponible':
            cur.close()
            conn.close()
            return jsonify({'error': 'El libro no está disponible'}), 400
        
        # Actualizar estado del libro
        cur.execute('UPDATE libros SET estado = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s', 
                   ('Prestado', book_id))
        
        # Registrar préstamo
        cur.execute('''
            INSERT INTO prestamos (libro_id, usuario_id, fecha_prestamo, estado) 
            VALUES (%s, %s, CURRENT_DATE, %s)
        ''', (book_id, current_user_id, 'Activo'))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'Libro "{book["titulo"]}" prestado exitosamente'
        })
    
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/books/<int:book_id>/return', methods=['POST'])
@token_required
def return_book(current_user_id, book_id):
    """Devolver un libro"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Error de conexión a la base de datos'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Verificar que el libro existe y está prestado
        cur.execute('SELECT * FROM libros WHERE id = %s', (book_id,))
        book = cur.fetchone()
        
        if not book:
            cur.close()
            conn.close()
            return jsonify({'error': 'Libro no encontrado'}), 404
        
        if book['estado'] != 'Prestado':
            cur.close()
            conn.close()
            return jsonify({'error': 'El libro no está prestado'}), 400
        
        # Actualizar estado del libro
        cur.execute('UPDATE libros SET estado = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s', 
                   ('Disponible', book_id))
        
        # Actualizar préstamo
        cur.execute('''
            UPDATE prestamos 
            SET fecha_devolucion = CURRENT_DATE, estado = %s 
            WHERE libro_id = %s AND estado = %s
        ''', ('Devuelto', book_id, 'Activo'))
        
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'Libro "{book["titulo"]}" devuelto exitosamente'
        })
    
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
@token_required
def get_stats(current_user_id):
    """Obtener estadísticas de la biblioteca"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Error de conexión a la base de datos'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Total de libros
        cur.execute('SELECT COUNT(*) as total FROM libros')
        total_books = cur.fetchone()['total']
        
        # Libros disponibles
        cur.execute('SELECT COUNT(*) as available FROM libros WHERE estado = %s', ('Disponible',))
        available_books = cur.fetchone()['available']
        
        # Libros prestados
        cur.execute('SELECT COUNT(*) as borrowed FROM libros WHERE estado = %s', ('Prestado',))
        borrowed_books = cur.fetchone()['borrowed']
        
        # Categorías únicas
        cur.execute('SELECT COUNT(DISTINCT categoria) as categories FROM libros')
        categories = cur.fetchone()['categories']
        
        cur.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'stats': {
                'total_books': total_books,
                'available_books': available_books,
                'borrowed_books': borrowed_books,
                'categories': categories
            }
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/categories', methods=['GET'])
@token_required
def get_categories(current_user_id):
    """Obtener todas las categorías"""
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Error de conexión a la base de datos'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT DISTINCT categoria FROM libros ORDER BY categoria')
        categories = cur.fetchall()
        
        cur.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'categories': [cat['categoria'] for cat in categories]
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/books', methods=['POST'])
@token_required
def add_book(current_user_id):
    """Agregar un nuevo libro"""
    try:
        data = request.get_json()
        required_fields = ['titulo', 'autor', 'categoria']
        
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Campo {field} requerido'}), 400
        
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Error de conexión a la base de datos'}), 500
        
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute('''
            INSERT INTO libros (titulo, autor, categoria, isbn, año, descripcion, estado) 
            VALUES (%s, %s, %s, %s, %s, %s, %s) 
            RETURNING id
        ''', (
            data['titulo'],
            data['autor'],
            data['categoria'],
            data.get('isbn', ''),
            data.get('año'),
            data.get('descripcion', ''),
            'Disponible'
        ))
        
        book_id = cur.fetchone()['id']
        conn.commit()
        cur.close()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Libro agregado exitosamente',
            'book_id': book_id
        }), 201
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Verificar estado de la API"""
    return jsonify({
        'status': 'OK',
        'message': 'API de Biblioteca funcionando correctamente',
        'timestamp': datetime.datetime.now().isoformat()
    })

if __name__ == '__main__':
    # Inicializar base de datos
    print("Inicializando base de datos...")
    if init_database():
        print("✅ Base de datos inicializada correctamente")
        print("🚀 Iniciando servidor Flask...")
        print("📚 API de Biblioteca disponible")
        print("🔐 Usuario de prueba: admin / 123456")
        
        # Para producción en Render
        port = int(os.environ.get('PORT', 5000))
        app.run(debug=False, host='0.0.0.0', port=port)
    else:
        print("❌ Error inicializando base de datos")
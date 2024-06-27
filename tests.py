import pytest
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token
from api import app, db, User, BugClassification, Classification

@pytest.fixture(scope='module')
def test_client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['JWT_SECRET_KEY'] = 'super-secret'
    db.create_all()
    with app.test_client() as testing_client:
        with app.app_context():
            yield testing_client
    db.drop_all()

def test_signup(test_client):
    response = test_client.post('/signup', json={
        'username': 'testuser',
        'password': 'testpassword',
        'email': 'testuser@example.com'
    })
    assert response.status_code == 201
    assert response.json['msg'] == 'User signed up successfully'

def test_login(test_client):
    test_client.post('/signup', json={
        'username': 'testuser',
        'password': 'testpassword',
        'email': 'testuser@example.com'
    })
    response = test_client.post('/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert response.status_code == 200
    assert 'access_token' in response.json

def test_create_bug_classification(test_client):
    access_token = create_access_token(identity='testuser')
    response = test_client.post('/bug_classification', json={
        'bugReportDetails': 'Sample bug report',
        'modelConfiguration': 'Sample model config'
    }, headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 201
    assert response.json['message'] == 'Bug classification created successfully.'

def test_get_bug_classification(test_client):
    access_token = create_access_token(identity='testuser')
    test_client.post('/bug_classification', json={
        'bugReportDetails': 'Sample bug report',
        'modelConfiguration': 'Sample model config'
    }, headers={'Authorization': f'Bearer {access_token}'})
    response = test_client.get('/bug_classification/1', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    assert 'classifications' in response.json

def test_update_bug_classification(test_client):
    access_token = create_access_token(identity='testuser')
    test_client.post('/bug_classification', json={
        'bugReportDetails': 'Sample bug report',
        'modelConfiguration': 'Sample model config'
    }, headers={'Authorization': f'Bearer {access_token}'})
    response = test_client.put('/bug_classification/1', json={
        'bugReportDetails': 'Updated bug report',
        'modelConfiguration': 'Updated model config'
    }, headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    assert response.json['message'] == 'Bug classification updated successfully.'

def test_delete_bug_classification(test_client):
    access_token = create_access_token(identity='testuser')
    test_client.post('/bug_classification', json={
        'bugReportDetails': 'Sample bug report',
        'modelConfiguration': 'Sample model config'
    }, headers={'Authorization': f'Bearer {access_token}'})
    response = test_client.delete('/bug_classification/1', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    assert response.json['message'] == 'Bug classification deleted successfully.'


def test_signup(test_client):
    response = test_client.post('/signup', json={
        'username': 'newuser',
        'password': 'newpassword',
        'email': 'newuser@test.com'
    })
    assert response.status_code == 201
    assert response.json['msg'] == 'User signed up successfully'

def test_login_with_new_user(test_client):
    response = test_client.post('/login', json={
        'username': 'newuser',
        'password': 'newpassword'
    })
    assert response.status_code == 200
    assert 'access_token' in response.json

def test_create_bug_classification_with_new_user(test_client):
    access_token = create_access_token(identity='newuser')
    response = test_client.post('/bug_classification', json={
        'bugReportDetails': 'Sample bug report',
        'modelConfiguration': 'Sample model config'
    }, headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 201
    assert response.json['message'] == 'Bug classification created successfully.'

def test_get_bug_classification_with_new_user(test_client):
    access_token = create_access_token(identity='newuser')
    test_client.post('/bug_classification', json={
        'bugReportDetails': 'Sample bug report',
        'modelConfiguration': 'Sample model config'
    }, headers={'Authorization': f'Bearer {access_token}'})
    response = test_client.get('/bug_classification/1', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    assert 'classifications' in response.json

def test_update_bug_classification_with_new_user(test_client):
    access_token = create_access_token(identity='newuser')
    test_client.post('/bug_classification', json={
        'bugReportDetails': 'Sample bug report',
        'modelConfiguration': 'Sample model config'
    }, headers={'Authorization': f'Bearer {access_token}'})
    response = test_client.put('/bug_classification/1', json={
        'bugReportDetails': 'Updated bug report',
        'modelConfiguration': 'Updated model config'
    }, headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    assert response.json['message'] == 'Bug classification updated successfully.'

def test_delete_bug_classification_with_new_user(test_client):
    access_token = create_access_token(identity='newuser')
    test_client.post('/bug_classification', json={
        'bugReportDetails': 'Sample bug report',
        'modelConfiguration': 'Sample model config'
    }, headers={'Authorization': f'Bearer {access_token}'})
    response = test_client.delete('/bug_classification/1', headers={'Authorization': f'Bearer {access_token}'})
    assert response.status_code == 200
    assert response.json['message'] == 'Bug classification deleted successfully.'

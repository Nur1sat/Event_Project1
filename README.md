# JIHC Clubs Activity Web App

Веб-приложение для управления клубными мероприятиями в JIHC (Jambyl Innovation High College).

## Технологии

### Backend
- FastAPI
- SQLAlchemy
- SQLite
- Python 3.12+

### Frontend
- Vue.js 3
- Vue Router
- Pinia
- Tailwind CSS
- Vite

## Установка

### Backend

```bash
cd backend
python3 -m venv venv
source venv/bin/activate  # На Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Frontend

```bash
cd frontend
npm install
```

## Запуск

### Backend

```bash
cd backend
source venv/bin/activate
uvicorn main:app --reload
```

Backend будет доступен на `http://localhost:8000`

### Frontend

```bash
cd frontend
npm run dev
```

Frontend будет доступен на `http://localhost:5173`

## Дефолтный администратор

При первом запуске создается дефолтный администратор:
- Email: `admin@jihc.kz`
- Password: `admin123`

## Функции

- Регистрация и авторизация пользователей
- Управление мероприятиями (CRUD)
- Регистрация на мероприятия
- Календарь мероприятий
- Запросы на создание мероприятий от студентов
- Профиль пользователя с фото
- **AI генерация описаний мероприятий** (опционально)

## AI Генерация Описаний

Система поддерживает два режима генерации описаний:

### 1. Шаблонная система (по умолчанию)
Работает без дополнительной настройки. Использует умные шаблоны на основе ключевых слов.

### 2. Реальный AI (OpenAI) - опционально
Для использования реального AI:

1. Получите API ключ от OpenAI: https://platform.openai.com/api-keys
2. Создайте файл `.env` в папке `backend/`:
   ```bash
   cd backend
   cp .env.example .env
   ```
3. Добавьте ваш API ключ в `.env`:
   ```
   OPENAI_API_KEY=sk-your-api-key-here
   ```
4. Перезапустите backend сервер

**Примечание:** Если API ключ не указан, система автоматически использует шаблонную генерацию.


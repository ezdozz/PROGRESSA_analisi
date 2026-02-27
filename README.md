# PROGRESSA_analisi

## Codebase Explanation: `job-search-app`

### 1. What Is This Application?

`job-search-app` is a **full-stack web application** designed to help job seekers manage their entire job search process — from tracking applications, to preparing for interviews, to managing CVs and building behavioral stories (STAR method). It integrates **Google Gemini AI** to provide intelligent insights, interview preparation, and story coaching.

The app is written in **Italian** (UI text and AI prompts), targeting an Italian-speaking user base.

---

### 2. Tech Stack

| Layer | Technology | Version |
|---|---|---|
| **Framework** | Next.js (App Router) | 15.1.6 |
| **Language** | TypeScript | 5.x |
| **UI** | React + Tailwind CSS | React 19, Tailwind 3.4 |
| **Database** | SQLite via Prisma ORM | Prisma 6.3 |
| **Authentication** | NextAuth.js (JWT strategy) | 4.24 |
| **AI** | Google Gemini (`gemini-flash-lite-latest`) | @google/generative-ai 0.24 |
| **Validation** | Zod | 4.3 |
| **Web Scraping** | Cheerio | 1.2 |
| **Password Hashing** | bcryptjs | 3.0 |

---

### 3. Project Structure

```
job-search-app/
├── app/                          # Next.js App Router (pages + API routes)
│   ├── page.tsx                  # Landing page (public)
│   ├── layout.tsx                # Root layout (HTML shell, fonts, global providers)
│   ├── globals.css               # Tailwind + custom CSS
│   ├── actions.ts                # Shared server actions
│   ├── login/page.tsx            # Login page
│   ├── register/page.tsx         # Registration page
│   ├── actions/                  # Server Actions (AI-powered features)
│   │   ├── cv.ts                 # CV analysis actions
│   │   ├── job-extraction.ts     # Job posting data extraction
│   │   ├── questions.ts          # Question bank actions
│   │   ├── questions-to-ask.ts   # Questions-to-ask the interviewer
│   │   └── story-generation.ts   # AI story generation
│   ├── api/                      # REST API routes (Next.js Route Handlers)
│   │   ├── ai/                   # AI-powered endpoints
│   │   │   ├── contacts/         # AI contact suggestions
│   │   │   ├── generate/         # General AI generation
│   │   │   └── real-questions/   # Real interview questions scraping
│   │   ├── applications/         # CRUD for job applications
│   │   ├── auth/[...nextauth]/   # NextAuth authentication handler
│   │   ├── calendar/             # Calendar events CRUD
│   │   ├── cv/                   # CV versions CRUD
│   │   ├── feedback/             # User feedback submission
│   │   ├── interview-readiness/  # Interview readiness scoring
│   │   ├── profile/              # User profile management
│   │   ├── questions/            # Question bank CRUD + categories
│   │   ├── register/             # User registration
│   │   ├── reviews/              # App reviews/testimonials
│   │   ├── stories/              # STAR stories CRUD + AI review
│   │   ├── tasks/                # Task management CRUD
│   │   └── upload/               # File uploads (CV, avatar, feedback screenshots)
│   └── dashboard/                # Protected dashboard pages
│       ├── page.tsx              # Dashboard home (overview)
│       ├── layout.tsx            # Dashboard layout (sidebar + content)
│       ├── applications/         # Applications list + detail + new
│       ├── calendar/             # Calendar view
│       ├── cv/                   # CV management
│       ├── profile/              # User profile
│       ├── questions/            # Question bank browser
│       ├── questions-to-ask/     # Questions to ask interviewers
│       ├── stories/              # STAR stories editor + AI assistant
│       └── tasks/                # Task board
├── components/                   # Reusable React components
│   ├── applications/             # Application-specific components
│   ├── auth/                     # Auth page components (testimonials)
│   ├── calendar/                 # Calendar event modals
│   ├── cv/                       # CV card, edit, link modals
│   ├── dashboard/                # Dashboard widgets (inspiration, readiness)
│   ├── feedback/                 # Global feedback widget
│   ├── layout/                   # Sidebar navigation
│   ├── questions/                # Question modals (add, connect, behavioral)
│   ├── reviews/                  # Review submission components
│   ├── stories/                  # AI review modal, story actions
│   └── ui/                       # Generic UI components (hero background)
├── lib/                          # Shared utilities and configuration
│   ├── auth.ts                   # NextAuth configuration
│   ├── db.ts                     # Prisma client singleton
│   ├── gemini.ts                 # Google Gemini AI wrapper functions
│   ├── application-utils.ts      # Application helper functions
│   ├── category-colors.ts        # UI color mappings for categories
│   └── constants.ts              # App-wide constants
├── prisma/
│   ├── schema.prisma             # Database schema (14 models)
│   └── migrations/               # Database migration history
├── public/                       # Static assets
│   ├── companies/                # Company logos
│   ├── landing/                  # Landing page assets
│   ├── logos/                    # Brand logos
│   └── uploads/                  # User uploads (avatars, CVs)
├── scripts/                      # Utility scripts
│   ├── seed_questions.ts         # Seed question bank from JSON
│   ├── verify_db.ts              # Database verification
│   ├── download_logos.js         # Logo downloader
│   ├── parse_docx.js             # DOCX parser for questions
│   └── check-models.ts          # Gemini model availability checker
├── types/
│   └── next-auth.d.ts            # NextAuth type extensions
├── middleware.ts                  # Route protection (dashboard/* requires auth)
├── .env                          # Environment variables
├── package.json                  # Dependencies and scripts
├── tailwind.config.ts            # Tailwind CSS configuration
└── tsconfig.json                 # TypeScript configuration
```

---

### 4. Database Schema (14 Models)

The database is **SQLite** (file-based: `dev.db`), managed through **Prisma ORM**. Here are all 14 models and their relationships:

#### Core Models

| Model | Purpose |
|---|---|
| **User** | Registered users. Has email/password auth. Stores profile info (name, target role, location, LinkedIn, avatar). |
| **Application** | A job application the user is tracking. Contains job details (title, company, description, tags, salary, stage) and links to contacts, AI insights, interview prep, tasks, calendar events, and CV versions. |
| **Task** | To-do items tied to a user and optionally to an application. Types: FOLLOW_UP, PREP, UPDATE, NETWORKING, CUSTOM. |
| **CalendarEvent** | Calendar entries. Can be linked to a Task (auto-created) or manually created. |

#### CV & Documents

| Model | Purpose |
|---|---|
| **CVVersion** | Uploaded CV files with metadata (title, role tags, file path). Multiple CVs per user, linkable to specific applications. |

#### AI & Intelligence

| Model | Purpose |
|---|---|
| **AIInsights** | AI-generated analysis of a job posting: company summary, role summary, key responsibilities, required skills, CV keywords, fit analysis, and a full strategic dossier. One-to-one with Application. |
| **InterviewPrep** | AI-generated interview preparation: motivation ideas, study topics, questions to ask, prep tasks, email templates, mapped stories, and practice log. One-to-one with Application. |
| **RealQuestions** | Real interview questions scraped from the web for a specific company/role. One-to-one with Application. |

#### Stories & Questions

| Model | Purpose |
|---|---|
| **Story** | Behavioral interview stories in STAR format (Situation, Task, Action, Result). Includes competencies, categories, tags, a discursive narrative version, and pin/favorite status. |
| **Question** | A bank of interview questions with macro-area categorization (seeded from a PDF/JSON source). |
| **QuestionStoryLink** | Many-to-many link between Questions and Stories, with AI confidence scores and origin tracking (AUTO/MANUAL). |
| **QuestionToAsk** | Questions the user wants to ask interviewers, categorized by difficulty and context. |

#### Feedback & Reviews

| Model | Purpose |
|---|---|
| **Feedback** | User feedback about the app (bug reports, suggestions) with optional screenshots. |
| **Review** | Public reviews/testimonials for the app's landing page, with approval workflow (PENDING/APPROVED/REJECTED). |

#### Key Relationships

```
User ──< Application ──< Contact
  │         │──── AIInsights (1:1)
  │         │──── InterviewPrep (1:1)
  │         │──── RealQuestions (1:1)
  │         │──< Task ──── CalendarEvent (1:1)
  │         │──< CalendarEvent
  │         └──── CVVersion
  │──< Story ──< QuestionStoryLink >── Question
  │──< Task
  │──< CalendarEvent
  │──< CVVersion
  │──< QuestionToAsk
  └──< Feedback
```

---

### 5. Authentication System

- **NextAuth.js** with **JWT** session strategy (no server-side session store needed)
- **4 providers configured:**
  1. **Credentials** — email + password (bcryptjs hashed)
  2. **Google OAuth**
  3. **LinkedIn OAuth**
  4. **GitHub OAuth**
- **Google SSO flow:** On first Google login, a new User record is auto-created in the database with a random password hash (the user will always sign in via Google, so the password is never used)
- **JWT callback:** Always resolves the real database UUID for the user, even when coming from an OAuth provider. This ensures all data (applications, stories, etc.) links correctly to the Prisma User model.
- **Middleware:** `middleware.ts` protects all `/dashboard/*` routes — unauthenticated users are redirected to `/login`

---

### 6. AI Integration (Google Gemini)

The app uses **Google Gemini** (`gemini-flash-lite-latest` model) through the `@google/generative-ai` SDK. All AI calls go through `lib/gemini.ts`, which provides these specialized functions:

| Function | What It Does |
|---|---|
| `callGemini(prompt)` | Base function — sends any prompt to Gemini and returns text |
| `callGeminiForJobInsights(jobDescription)` | Analyzes a job posting → returns company summary, role summary, responsibilities, skills (must-have + nice-to-have), CV keywords, fit analysis |
| `callGeminiForStrategicDossier(...)` | Generates a full executive briefing for interview prep: company overview, history, strategy, role intelligence, preparation areas, interview themes, smart questions to ask |
| `callGeminiForInterviewPrep(...)` | Creates practical interview prep: motivation ideas, study focus areas, questions to ask, prep tasks, thank-you and follow-up email templates |
| `suggestLinkedQuestionsForStory(...)` | Maps a STAR story to the most relevant questions from the question bank (with confidence scores 0-100) |
| `reviewStarStory(...)` | AI coaching on a STAR story: strengths, weaknesses, improvement suggestions, and a full suggested rewrite |
| `callGeminiForContacts(...)` | Suggests likely recruiter/hiring manager contacts at a company with LinkedIn search URLs |

All prompts request **JSON-only output** and include defensive parsing (stripping markdown fences, finding the first `{` to last `}`).

All AI prompts are in **Italian** (except the contacts function which is in English).

---

### 7. Key Features (Dashboard Sections)

#### 7.1 Applications (`/dashboard/applications`)
- Track job applications through stages: TO_APPLY → APPLIED → SCREENING_CALL → ... (full pipeline)
- Store full job descriptions, company info, salary, tags, priority level
- AI-powered: auto-extract insights from job descriptions, generate strategic dossiers
- Manage contacts per application (manual or AI-suggested)
- Link CV versions to specific applications
- Scrape real interview questions from the web

#### 7.2 Stories (`/dashboard/stories`)
- Create and manage STAR behavioral stories (Situation, Task, Action, Result)
- AI assistant for story generation and coaching
- AI review: get feedback on story quality with suggested rewrites
- Auto-link stories to relevant interview questions (with confidence scores)
- Generate discursive (narrative) versions of stories
- Pin/favorite and tag stories by competency

#### 7.3 Questions (`/dashboard/questions`)
- Pre-seeded question bank (imported from PDF/JSON via scripts)
- Categorized by macro-areas (behavioral, technical, etc.)
- Link questions to stories (manually or via AI)
- Browse by category

#### 7.4 Questions to Ask (`/dashboard/questions-to-ask`)
- Curate questions to ask interviewers
- Categorized by difficulty (Basic, Strategic, Advanced) and context tags
- Record answers received from interviewers
- Pin/favorite important questions

#### 7.5 CV Management (`/dashboard/cv`)
- Upload multiple CV versions (file storage in `public/uploads/cv/`)
- Tag CVs by target role
- Link specific CV versions to applications

#### 7.6 Calendar (`/dashboard/calendar`)
- Visual calendar for scheduling
- Auto-created events from tasks (with due dates)
- Manual event creation
- Linked to applications and tasks

#### 7.7 Tasks (`/dashboard/tasks`)
- Task board for job search activities
- Types: Follow-up, Prep, Update, Networking, Custom
- Linked to applications
- Status tracking (TODO/DONE)
- Auto-creates calendar events when tasks have due dates

#### 7.8 Profile (`/dashboard/profile`)
- User profile management (name, target role, location, LinkedIn, avatar)
- Avatar upload or gradient selection

#### 7.9 Dashboard Home (`/dashboard`)
- Daily inspiration widget
- Interview readiness widget (scores how prepared you are)
- Overview of recent activity

---

### 8. API Routes Summary

All API routes are under `app/api/` using Next.js Route Handlers:

| Endpoint | Methods | Description |
|---|---|---|
| `/api/auth/[...nextauth]` | GET, POST | NextAuth authentication |
| `/api/register` | POST | New user registration |
| `/api/profile` | GET, PUT | User profile CRUD |
| `/api/applications` | GET, POST | List/create applications |
| `/api/applications/[id]` | GET, PUT, DELETE | Single application CRUD |
| `/api/applications/[id]/contacts` | GET, POST | Application contacts |
| `/api/applications/[id]/contacts/[contactId]` | PUT, DELETE | Single contact CRUD |
| `/api/cv` | GET, POST | List/upload CVs |
| `/api/cv/[id]` | PUT, DELETE | Single CV CRUD |
| `/api/calendar` | GET, POST | List/create events |
| `/api/calendar/[id]` | PUT, DELETE | Single event CRUD |
| `/api/questions` | GET, POST | Question bank CRUD |
| `/api/questions/[id]` | PUT, DELETE | Single question CRUD |
| `/api/questions/categories` | GET | List question categories |
| `/api/stories` | GET, POST | STAR stories CRUD |
| `/api/stories/[id]` | GET, PUT, DELETE | Single story CRUD |
| `/api/stories/review` | POST | AI story review |
| `/api/tasks` | GET, POST | Task management |
| `/api/feedback` | POST | Submit app feedback |
| `/api/reviews` | GET, POST | App reviews/testimonials |
| `/api/interview-readiness` | GET | Interview readiness score |
| `/api/upload` | POST | General file upload |
| `/api/upload/avatar` | POST | Avatar image upload |
| `/api/upload/feedback` | POST | Feedback screenshot upload |
| `/api/ai/generate` | POST | General AI content generation |
| `/api/ai/contacts` | POST | AI contact suggestions |
| `/api/ai/real-questions` | POST | Scrape real interview questions |

---

### 9. Server Actions

Located in `app/actions/`, these are Next.js Server Actions (called directly from client components):

| File | Purpose |
|---|---|
| `cv.ts` | CV analysis and processing |
| `job-extraction.ts` | Extract structured data from job posting URLs/text |
| `questions.ts` | Question bank operations |
| `questions-to-ask.ts` | CRUD for questions to ask interviewers |
| `story-generation.ts` | AI-powered STAR story generation |

---

### 10. Environment Variables

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | SQLite database path (`file:./dev.db`) |
| `NEXTAUTH_SECRET` | JWT signing secret for NextAuth |
| `NEXTAUTH_URL` | Base URL for auth callbacks (`http://localhost:3000`) |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | Google OAuth credentials |
| `GEMINI_API_KEY` | Google Gemini AI API key |
| `PERPLEXITY_API_KEY` | Perplexity API key (likely used for real questions scraping) |

---

### 11. How to Run Locally

```bash
# 1. Install dependencies
npm install

# 2. Generate Prisma client
npx prisma generate

# 3. Create/migrate the database
npx prisma migrate dev

# 4. (Optional) Seed the question bank
npx ts-node scripts/seed_questions.ts

# 5. Start development server
npm run dev
```

The app runs at `http://localhost:3000`.

---

### 12. Architecture Patterns

- **App Router**: Uses Next.js 15 App Router with `page.tsx` for pages and `route.ts` for API endpoints
- **Server/Client split**: Pages use `page.tsx` (server component) for data fetching and `client.tsx` for interactive UI
- **Prisma Singleton**: `lib/db.ts` uses the global singleton pattern to avoid multiple Prisma instances in development
- **JSON-in-SQLite**: Complex arrays/objects (tags, skills, dossier data) are stored as JSON strings in SQLite text columns, parsed at runtime
- **AI prompt → JSON**: All Gemini interactions follow a consistent pattern: structured prompt (Italian) → request JSON-only response → defensive parsing with fallback
- **File uploads**: Stored directly in `public/uploads/` (avatars, CVs, feedback screenshots) — served as static files by Next.js

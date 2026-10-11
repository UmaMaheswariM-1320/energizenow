import { pool } from './db.js';

const tables = [
`CREATE TABLE IF NOT EXISTS departments (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(100) NOT NULL, monthly_budget DECIMAL(12,2))`,
`CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY AUTO_INCREMENT, employee_code VARCHAR(20) UNIQUE, name VARCHAR(100) NOT NULL, email VARCHAR(120) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, role ENUM('employee','manager','finance','admin') DEFAULT 'employee', department_id INT, manager_id INT, is_active BOOLEAN DEFAULT TRUE, FOREIGN KEY (department_id) REFERENCES departments(id), FOREIGN KEY (manager_id) REFERENCES users(id))`,
`CREATE TABLE IF NOT EXISTS categories (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(80) NOT NULL, daily_limit DECIMAL(10,2), receipt_required BOOLEAN DEFAULT TRUE)`,
`CREATE TABLE IF NOT EXISTS reports (id INT PRIMARY KEY AUTO_INCREMENT, user_id INT NOT NULL, title VARCHAR(150), purpose TEXT, total_amount DECIMAL(12,2) DEFAULT 0, status ENUM('draft','submitted','manager_approved','approved','rejected','reimbursed') DEFAULT 'draft', submitted_at DATETIME, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users(id))`,
`CREATE TABLE IF NOT EXISTS expenses (id INT PRIMARY KEY AUTO_INCREMENT, user_id INT NOT NULL, report_id INT, category_id INT NOT NULL, expense_date DATE NOT NULL, merchant VARCHAR(120), amount DECIMAL(10,2) NOT NULL, currency CHAR(3) DEFAULT 'INR', payment_mode ENUM('cash','card','upi','bank'), description TEXT, receipt_path VARCHAR(255), is_billable BOOLEAN DEFAULT FALSE, policy_flag BOOLEAN DEFAULT FALSE, FOREIGN KEY (user_id) REFERENCES users(id), FOREIGN KEY (report_id) REFERENCES reports(id), FOREIGN KEY (category_id) REFERENCES categories(id))`,
`CREATE TABLE IF NOT EXISTS approvals (id INT PRIMARY KEY AUTO_INCREMENT, report_id INT NOT NULL, approver_id INT NOT NULL, level TINYINT NOT NULL, decision ENUM('pending','approved','rejected','returned') DEFAULT 'pending', comment TEXT, decided_at DATETIME, FOREIGN KEY (report_id) REFERENCES reports(id), FOREIGN KEY (approver_id) REFERENCES users(id))`,
`CREATE TABLE IF NOT EXISTS reimbursements (id INT PRIMARY KEY AUTO_INCREMENT, report_id INT NOT NULL, paid_amount DECIMAL(12,2), paid_on DATE, reference_no VARCHAR(60), FOREIGN KEY (report_id) REFERENCES reports(id))`,
`CREATE TABLE IF NOT EXISTS notifications (id INT PRIMARY KEY AUTO_INCREMENT, user_id INT NOT NULL, message VARCHAR(255), is_read BOOLEAN DEFAULT FALSE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`,
`CREATE TABLE IF NOT EXISTS audit_log (id INT PRIMARY KEY AUTO_INCREMENT, user_id INT, action VARCHAR(100), entity VARCHAR(50), entity_id INT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`,
];

export async function ensureSchema() {
  for (const sql of tables) await pool.query(sql);
}
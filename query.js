require('dotenv').config();
const { pool, shutdown } = require('./db');

async function getRegisteredEmails() {
  try {
    if (!process.env.DATABASE_URL || process.env.DATABASE_URL.includes('password@localhost')) {
      console.error('❌ Error: Please set your active DATABASE_URL in the .env file first.');
      process.exit(1);
    }
    
    console.log('Connecting to database...');
    const result = await pool.query('SELECT name, email, role FROM users ORDER BY created_at DESC');
    
    console.log('\n--- Registered Users ---');
    if (result.rows.length === 0) {
      console.log('No users registered yet.');
    } else {
      result.rows.forEach((user, index) => {
        console.log(`${index + 1}. ${user.email} (Name: ${user.name}, Role: ${user.role})`);
      });
    }
    console.log('------------------------\n');
  } catch (error) {
    console.error('Error executing query:', error.message);
  } finally {
    await shutdown();
  }
}

getRegisteredEmails();

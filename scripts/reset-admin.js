require('dotenv').config();
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
(async()=>{
  if(!process.env.DATABASE_URL) throw new Error('DATABASE_URL 환경변수가 필요합니다.');
  const username=process.env.RESET_ADMIN_USERNAME || process.env.ADMIN_USERNAME;
  const password=process.env.RESET_ADMIN_PASSWORD;
  if(!username || !password || password.length<12) throw new Error('RESET_ADMIN_USERNAME과 RESET_ADMIN_PASSWORD(12자 이상)를 설정하세요.');
  const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.PGSSL==='disable'?false:(process.env.NODE_ENV==='production'?{rejectUnauthorized:false}:undefined)});
  try {
    const hash=await bcrypt.hash(password,12);
    const result=await pool.query('UPDATE admins SET password_hash=$1,updated_at=NOW() WHERE username=$2',[hash,username]);
    if(!result.rowCount) throw new Error(`관리자 '${username}' 계정을 찾지 못했습니다. 최초 계정은 ADMIN_USERNAME/ADMIN_PASSWORD로 생성하세요.`);
    console.log(`관리자 '${username}'의 비밀번호를 재설정했습니다.`);
  } finally { await pool.end(); }
})().catch(e=>{console.error(e.message);process.exit(1)});

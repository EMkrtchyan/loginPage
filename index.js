import express, { text } from "express";
import path from "path";
import bcrypt from "bcrypt";
import fs from "fs";


const app = express();
app.use(express.static("public"));
app.use(express.urlencoded({extended:true}));
const filePath = path.resolve("data.json");


async function register(newData) {
    try {
        // Read the file
        const data = await fs.promises.readFile('data.json', 'utf8');

        // Parse the JSON file content
        const jsonData = data.trim() ? JSON.parse(data) : [];

        // Push new data to the array
        jsonData.push(newData);

        // Write updated data back to the JSON file
        await fs.promises.writeFile('data.json', JSON.stringify(jsonData, null, 4));
        console.log('Data successfully added to the file!');
    } catch (err) {
        if (err.code === 'ENOENT') {
            // Handle the case where the file does not exist
            console.error('File not found, creating a new one...');
            const jsonData = [newData];
            await fs.writeFile('data.json', JSON.stringify(jsonData, null, 4));
            console.log('File created and data added!');
        } else if (err.name === 'SyntaxError') {
            // Handle JSON parsing errors
            console.error('Error parsing JSON:', err);
        } else {
            // Handle other errors
            console.error('Error handling file:', err);
        }
    }
}

async function getUserByEmail(email) {
    try {
        // Read and parse the JSON file
        const data = await fs.promises.readFile('data.json', 'utf8');
        const users = JSON.parse(data);
        // Find the user by email
        const user = users.find(user => user.email === email);
        // Return the user or a message if not found
        return user ;
    } catch (err) {
        console.error('Error reading or parsing the file:', err);
        throw err;
    }
}

async function checkUser(pwd,email){
    const user = await getUserByEmail(email);
    if(user)
    {
        const hash = user.password
        console.log(pwd,hash)
        return await bcrypt.compare(pwd, hash);
    }
    else
    {
        return false 
    }
}

app.post("/", async (req,res)=>{
    let log_data = req.body;
    const filePath = path.resolve("data.json");

    const email = log_data.email
    const result = await checkUser(log_data.password,email)

    if(result)
        {
            console.log("correct password")
        }
    else
        {
            console.log("wrong password")
        }
});




app.get("/register",(req,res)=>{
    res.sendFile(path.resolve("public/register/register.html"));
});
app.get("/login",(req,res)=>{
    res.sendFile(path.resolve("public/login/login.html"));
});

app.post("/",  (req,res)=>{
    let log_data = req.body;
    const filePath = path.resolve("userdata.json");
    fs.promises.readFile(filePath,'utf-8').then(async(data)=>{
        const parsedData = JSON.parse(data);
        const checkPwd = await bcrypt.hash(log_data.password,10);
        bcrypt.compare(log_data.password,parsedData[0].password,(err)=>{
            if(!err){
                console.error('Error comparing passwords:', err);
                return;
            }
        })
        console.log(checkPwd);
        console.log(parsedData[0].password);
    });

});
app.post("/login",async (req,res)=>{
    const {firstName,lastName,email,password} = req.body;
    const hashPwd = await bcrypt.hash(password,10);
    register({
        firstName,
        lastName,
        email,
        password:hashPwd
    });
    res.redirect(path.resolve("/login"));
});


app.listen(3001);
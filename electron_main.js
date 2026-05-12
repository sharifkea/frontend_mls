// electron_main.js
const { app, BrowserWindow, ipcMain } = require('electron');
const { spawn } = require('child_process');
const path = require('path');

let flaskProcess = null;
let mainWindow = null;

function startFlask() {
    // Start Flask as a child process
    flaskProcess = spawn('python', [
        path.join(__dirname, 'app.py')
    ], {
        env: { ...process.env, PORT: 5000 }
    });
    
    flaskProcess.stdout.on('data', (data) => {
        console.log(`Flask: ${data}`);
        // When Flask is ready, load the Electron window
        if (data.toString().includes('Running on')) {
            createWindow();
        }
    });
    
    flaskProcess.stderr.on('data', (data) => {
        console.error(`Flask Error: ${data}`);
    });
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        webPreferences: {
            nodeIntegration: true,
            contextIsolation: false
        }
    });
    
    // Load the local Flask server
    mainWindow.loadURL('http://localhost:5000');
    
    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}

app.whenReady().then(() => {
    startFlask();
});

app.on('window-all-closed', () => {
    if (flaskProcess) {
        flaskProcess.kill();
    }
    app.quit();
});
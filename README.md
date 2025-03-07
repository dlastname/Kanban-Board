# Kanban Board

## Description

This Kanban board application helps users efficiently manage tasks in an organized, visual workflow. Designed for agile teams and personal productivity, it allows users to create, update, and track tasks seamlessly.

To ensure security, the application features a secure login system powered by JSON Web Tokens (JWT). Users must authenticate before accessing the board, and sessions are securely managed to protect user data. The authentication system enables smooth login and logout functionality, prevents unauthorized access, and automatically expires inactive sessions.

## Table of Contents

If your README is long, add a table of contents to make it easy for users to find what they need.

- [Installation](#installation)
- [Usage](#usage)
- [License](#license)
- [Contributing](#contributing)
- [Tests](#tests)
- [Questions](#questions)

## Installation

To install the necessary dependencies, run the following command: 

`npm install`

This will install all neccessary node modules.

## Usage

This application is also deployed on render. You can find it [here](https://kanban-board-05eo.onrender.com).

If running natively using Vite, run the following after completeing installation:

`npm run build`

`npm run start`

This should open on your browser on localhost 3000.

To log in, use one of the accounts already seeded to the database.

![Log In Page](./client/public/LoginScreen.png?raw=true)

Once logged in, you'll see a Kanban board of all the tickets made.

![Alt text](./client/public/MainKanban.png?raw=true)

To make a new one select "New Ticket", fill out the forms, then submit. It should appear on the main kanban page under your selected status.

![Alt text](./client/public/CreateTicket.png?raw=true)



## License

This project is licensed under the MIT License. 
  [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) (https://opensource.org/licenses/MIT)

## Contributing

For now this project is locked down and private. No contribution will be accepted since this is a solo class project.

## Tests

N/A

## Questions

If you have any questions, feel free to contact me at dllorens28@gmail.com.  

Visit my GitHub profile: [dlastname](https://github.com/dlastname)

*Generated by [dlastname's Professional-README-Generator](https://github.com/dlastname/Professional-README-Generator)*


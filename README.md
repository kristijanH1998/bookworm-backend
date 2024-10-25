# BookWorm - Book Reading Application (Backend)
BookWorm - full-stack solo project for Bay Valley Tech Code Academy

## Table of Contents
- [Description](#description)
- [How to Run the Project](#how-to-run-the-project)
- [How to Use the Project](#how-to-use-the-project)
- [Documentation](#documentation)

## Description
#### Overview and Technologies used
* This is the first full-stack software project I developed independently on my own.
* Full-Stack book reading web application that lets users browse and select books from the Google Books digital database by communicating with Google Books API. 
* Searching of book records can be performed by three criteria: title, author name(s), and ISBN.
* BookWorm employs Google's Embedded Viewer API to display selected book's text on the screen for reading, within an Embedded Viewer window.
* The application also provides information about literary works from Google's database, and lets users perform CRUD operations on their profiles by updating their account data.
* Books can be placed into one or more of three categories: Favorites, Finished Reading, and Wishlist for future reading.
* The application maintains high level of security by employing hashed passwords (using bcrypt library), SQL injection prevention by means of name placeholders in SQL queries of requests sent from backend to the MySQL database, JWT token for user authentication, and other important security aspects.
* BookWorm's frontend was built on Arch Linux system in TypeScript, React.js, HTML5, CSS3, and Bootstrap, with help of tools like VS Code (for code editing), Figma (for wireframes), and Git (for software version control).
* The backend portion was developed in JavaScript using Node.js, Express.js, MySQL (MariaDB) and the tools utilized were VS Code, Postman (for backend testing), and Git on a Linux system.
* React Router is used on the frontend for page routing, Axios HTTP client library is used for sending REST API requests to the backend web server, while Google Books API receives requests from the backend, which backend receives from the frontend.
* The backend handles data transfer to and from the MySQL relational database managed with MySQL Workbench. Backend utilizes Express.js as server framework, bcrypt library for password hashing, CORS for application integration, JWT keys for authentication, and body-parser libary for HTTP request parsing.

#### Challenges faced during development (on Frontend)
* A particularly challenging part of development was including Google Books Embedded API viewer canvas on the Search Books page: TypeScript compiler initially threw errors indicating it does not recognize 'google' in 'google.books.load();' with messages 'Cannot find name 'google'' and 'google.books.load is not a function', and other errors with 'google' object's associated functions and classes ('.books' class, 'load()' method, etc.). 
This issue was mitigated by adding the following lines: <br>
``` 
<script type="text/javascript" src="https://www.google.com/books/jsapi.js"></script></xmp>
```
in index.html, and:
```
declare var google: any; 
```
in Home.tsx; It is not enough to just write these lines of code in Home.tsx before calling 'google.books.load();':
```
const script = document.createElement('script');
script.src = "https://www.google.com/books/jsapi.js";
script.type = "text/javascript"
document.body.appendChild(script);
```
it was necessary to also include the jsapi.js script in the script tag in index.html, and have 'declare var google: any;' in Home.tsx, as shown above.

* Another issue happened in this segment of code in Home.tsx (Search books webpage):
```
        useEffect(() => {
            if(page >= 0) {
                acquireJwt();
                // console.log(searchPhrase)
                axios
                    .get("http://localhost:3000/search-books", {
                    headers: {"authorization": "Bearer " + jwt}, 
                    params: {"search-terms": searchPhrase, criteria: searchPlaceholder, page: page * 10}})
                    .then((res) => {
                        if (res.data.success) {
                            // console.log(res.data.data.items)
                            // console.log(typeof res.data.data.items)
                            setBookList(res.data.data.items)
                            console.log(bookList)
                        } 
                    })
                    .catch((error) => {
                        console.log(error.response.data.error)
                    });
            }
            console.log(page)
        }, [page]) 
```        
This threw an error from the backend complaining about jwt key not being provided, 
because jwt key could not be fetched from local storage before /search-books endpoint is called, 
as it is called immediately on page load since page=0 right from the start. 
This made it impossible to send the /search-books request above whenever the condition page>=0 was 
true; it was only functional when page>0 condition was required, since by the time user
clicks on 'Next' button and increments value of page, jwt is already fetched from local storage and 
available, and endpoint request can be successful. This bug was fixed by including 'jwt' as 
condition in the if statement (like this: "if(jwt && page >= 0)"), since jwt was now first checked 
for value inside it and whether it was undefined before the /search-books endpoint request is sent.

* Another obstacle was when GET HTTP requests worked normally, but POST HTTP requests would send 
authorization error saying the authorization header content was undefined. This was fixed by 
following rules for POST request type, stating that Authorization header must come after the 
data parameter, unlike in GET type requests.

#### Future Work
* Due to OpenAI API not offering free tier for developers, I decided to abandon my original idea of implementing an AI feature that would answer user's questions about a text they are reading. If I find an AI query API that is offered for free or simply requires an API key to process requests, I will try to implement such a feature in the future.
* BookWorm should have a forum page where users can leave their comments on books they read and give them a rating. This was also part of my original idea for the app, but due to time constraints I had to postpone it for future development.
* A notebook window could be implemented on the Home (Search Books) page, with a button next to the Embedded Viewer that would open a modal for the user to write their notes into while reading the book. Although part of the original functional outline, this feature was never attempted, even though it could be somewhat easily implemented with Bootstrap elements. 

#### Motivation
* I decided to create this application to get more hands-on experience in full-stack 
software development, to explore the capabilities of integrating external (third-party) APIs
into my own applications, and to finish the Bay Valley Tech Code Academy learning path on which
I embarked in October 2023, with hopes of eventually obtaining a full-stack software development 
certificate. I saw this as a milestone which, once achieved, would enrich my CV and potentially 
kick-start my professional software engineering career.

#### Things I Learned
* Work on this app has taught me how much time and effort is required to build a full-stack
software project from ground up on one's own, without help from others. I had to be designer, developer,
engineer, database administrator, tester, and my own supervisor in order to bring this project to 
completion.

* I learned how stark a difference there can be between initial software project plans, functional 
outlines and design ideas, and actual implementation and practical realization of those plans, that is, the finished product.
BookWorm was according to my starting expectations supposed to incorporate OpenAI API feature which would answer
user's questions about books they are reading, a forum for users where they can share their opinions on books, 
and other elements which have not been implemented due to time constraints. Some day I might revisit this
project and include all those extra elements into it.

* Decision to build software in technologies and tools that require more technical considerations and
higher expertise should be made carefully. At a certain point of this project I decided to transform the 
frontend code from JavaScript to TypeScript, so to increase my knowledge of TypeScript development. I ended
up having to address a lot of data type issues with function parameters and React component props, and some
difficult to solve bugs which slowed the project down. But I think that learning a new skill is very
important in the start of one's career, and challenges should be welcomed, not feared.

## How to Run the Project
### Backend Installation
1. Download and install VS Code editor [here](https://code.visualstudio.com/download)
2. Use the terminal in VS Code (Bash, PowerShell, depending on the OS) to download and install Node.js, find instructions [here](https://nodejs.org/en/download/package-manager)
3. Use VS Code 'Extensions' page to search for and install latest version of 'HTML CSS Support' dependency (CSS Intellisense for HTML)
4. (optional) Use VS Code 'Extensions' page to search for and install latest version of 'JavaScript (ES6) code snippets'
5. Use VS Code 'Extensions' page to search for and install latest version of 'ESLint' to integrate ESLint JavaScript into your code editor
6. Follow instructions on [this](https://github.com/git-guides/install-git) link to install Git
7. Choose the location (directory) for the project repository, navigate to it with 'cd [directory-name]' terminal command and inside of it clone the project repository by running the command 'git clone https://github.com/kristijanH1998/bookworm-backend.git' in your terminal
8. Run the command 'npm i' to install all required dependencies
9. Install MySQL for Windows, follow instructions on [this link](https://dev.mysql.com/doc/refman/8.0/en/windows-installation.html); for Linux, follow instructions on [this link](https://dev.mysql.com/doc/refman/8.0/en/linux-installation.html)
10. Install MySQL Workbench. Follow instructions from [here](https://dev.mysql.com/doc/workbench/en/wb-installing.html)
11. Connect to the MySQL Server with MySQL Client. See instructions [here](https://dev.mysql.com/doc/mysql-getting-started/en/#mysql-getting-started-connecting)
12. Launch MySQL Workbench and create a new MySQL Connection: [tutorial](https://dev.mysql.com/doc/workbench/en/wb-getting-started-tutorial-create-connection.html) 
13. Obtain a Google Books API key. Check [here](https://developers.google.com/books/docs/v1/using#APIKey) for more on how this is done.
14. Create a .env file in the same directory where you cloned project repository from GitHub, and paste the following lines into the .env file:
```
DB_HOST         = localhost
DB_USER         = root
DB_PASSWORD     = [password you use for your database, entered in step 12 when new MySQL Workbench connection was created]
DB_NAME         = [name of your MySQL database]
DB_PORT         = [TCP/IP port of your database server host]

JWT_KEY         = [the signature/key which will be used for JWT encoding]

PORT            = [port of your local backend development server which will receive requests from frontend, usually 3000]  

API_KEY         = [your Google Books API key]
```
Don't forget to also create a .gitignore file in the project repository directory, and paste the following into it to prevent accidentally commiting your Google Books API key to your public GitHub repository:
```
node_modules
.env
```
15. Run the backend server by typing 'nodemon index.cjs' in the terminal (make sure you are in the backend repository directory). After this is done, proceed to running the frontend for BookWorm: [Run BookWorm Frontend](https://github.com/kristijanH1998/bookworm?tab=readme-ov-file#how-to-run-the-project) 

## How to Use the Project
* Instructions on how this app should be used can be found in the project's Frontend repository [here](https://github.com/kristijanH1998/bookworm?tab=readme-ov-file#how-to-use-the-project)

## Documentation
* The repository of the Frontend part of the project can be found [here](https://github.com/kristijanH1998/bookworm.git)
* Developer log for this project can be found [here](https://docs.google.com/document/d/1ieDdM0txky0wxEZ3w_PPIUdPI_pAFzgeKAzslnP2bsw/edit?usp=sharing)
* The Wireframes I made in Figma for this project can be found by clicking on [this link](https://www.figma.com/design/HyaA7HkQP4oVYABsiWcimn/BookWorm-Wireframe?node-id=0-1&t=0i8CE6GfiTgFVYkF-1)
* Functional Design Outline for BookWorm: [link](https://docs.google.com/document/d/1XoP50WMfJ7WNict0mYizXaeUk4Cqgh8SxsYhh9SBCIw/edit?usp=sharing)
* More screenshots of BookWorm can be seen on my [portfolio website](https://kristijanh1998.github.io/bookworm.html)

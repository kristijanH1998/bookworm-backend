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

#### Challenges faced during development (during Frontend development)
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

#### Features to be implemented in the future

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


## How to Use the Project
* Instructions on how this app should be used can be found in the project's Frontend repository[here](https://github.com/kristijanH1998/bookworm?tab=readme-ov-file#how-to-use-the-project)

## Documentation
* The repository of the Frontend part of the project can be found [here](https://github.com/kristijanH1998/bookworm.git)
* Developer log for this project can be found [here](https://docs.google.com/document/d/1ieDdM0txky0wxEZ3w_PPIUdPI_pAFzgeKAzslnP2bsw/edit?usp=sharing)
* The Wireframes I made in Figma for this project can be found by clicking on [this link](https://www.figma.com/design/HyaA7HkQP4oVYABsiWcimn/BookWorm-Wireframe?node-id=0-1&t=0i8CE6GfiTgFVYkF-1)
* Functional Design Outline for BookWorm: [link](https://docs.google.com/document/d/1XoP50WMfJ7WNict0mYizXaeUk4Cqgh8SxsYhh9SBCIw/edit?usp=sharing)
* More screenshots of BookWorm can be seen on my [portfolio website](https://kristijanh1998.github.io/bookworm.html)

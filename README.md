#  The Bazaar
A commerce app designed for auctions, where users can create profiles to either list items for auction or bid on others' listings. The app provides a dynamic and interactive platform for users to engage in buying and selling through auctions. Below is a detailed description of the features and functionalities of The Bazaar.

## Features

- User Authentication
  - Sign In and Register: Users can create a new account or sign in to an existing account to access the features of the app.
- User Profiles
  - Create and Edit Profile: Users can create and edit their profiles to personalize their experience.
  - View Other Users' Profiles: Users can view other users' profiles and contact them.
- Listings
  - Create Listing: Users can create new auction listings by specifying a title, description, starting bid, and optionally, an image URL and category (e.g., Fashion, Toys, Electronics, Home, etc.).
  - Active Listings Page: The default route of the application displays all currently active auction listings. Each listing shows the title, description, current price, and photo (if available).
  - Listing Page: Clicking on a listing takes users to a detailed page for that listing. Here, users can view all details, including the current price, and, if signed in, perform various actions:
    - Watchlist Management: Users can add or remove the item from their watchlist.
    - Place Bid: Users can place a bid, provided it meets the starting bid and is higher than any existing bids.
    - Close Auction: Users who created the listing can close the auction, making the highest bidder the winner and deactivating the listing.
    - Comments: Users can add comments to the listing, and all comments are displayed on the listing page.
- Watchlist
    - Watchlist Page: Signed-in users can visit a page displaying all listings they have added to their watchlist. Clicking on a listing navigates to its detailed page.
- Categories
  - Categories Page: Users can visit a page that lists all categories. Clicking on a category displays all active listings within that category.
- Closed Listings
  - View Closed Listings: Users can view listings they have won after the auction is closed.
  
## Implementation

- HTML: Structured the web pages with HTML elements, including forms, input fields, buttons, and links.
- CSS: Styled the pages in a light mode, using light and brown colors, rounded corners, and consistent button styling.

## Development

This project was developed while taking the Harvard virtual class CS50's Web Programming with Python, HTML, CSS and JavaScript. It served as a practical exercise to reinforce concepts learned during the course.

## Usage

1. Clone the repository: git clone https://github.com/your_username/thebazaar.git
2. Navigate to the project directory.
3. Install dependencies: pip install -r requirements.txt
4. Run the Django application: python app.py / python managepy runserver
5. Open your web browser and go to http://localhost:5000 to start using The Bazaar.

## Demonstrative Video 
https://www.youtube.com/watch?v=is8PS5UrMyY

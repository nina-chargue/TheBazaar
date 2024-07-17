from django.contrib.auth import authenticate, login, logout
from django.db import IntegrityError
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import redirect, render, get_object_or_404
from django.urls import reverse
from django.contrib import messages
from .models import AuctionImage, User, AuctionListing, Bid, Comment, Category, Watchlist
from decimal import Decimal, DecimalException, InvalidOperation
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
import os
import cloudinary
import cloudinary.uploader
import cloudinary.api
import hashlib
import hmac
import time
from cloudinary.uploader import upload, destroy

def index(request):
    """
    Renders all categories and active auction listings. And filters 
    active listings by category based on request parameters.
    """
    categories = Category.objects.all()
    active_listings = AuctionListing.objects.filter(state='Active')

    category_filter = request.GET.get('category')
    if category_filter:
        active_listings = active_listings.filter(category__name=category_filter)

    return render(request, 'auctions/index.html', {'active_listings': active_listings, 'categories': categories, 'category_filter': category_filter})

def login_view(request):
    """
    Handle user login.
    """
    if request.method == "POST":
        # Attempt to sign user in
        username = request.POST["username"]
        password = request.POST["password"]
        user = authenticate(request, username=username, password=password)

        # Check if authentication successful
        if user is not None:
            login(request, user)
            return HttpResponseRedirect(reverse("index"))
        else:
            return render(request, "auctions/login.html", {
                "message": "Invalid username and/or password."
            })
    else:
        return render(request, "auctions/login.html")

def logout_view(request):
    """
    Log out the currently authenticated user and redirect to the index page.
    """
    logout(request)
    return HttpResponseRedirect(reverse("index"))

def register(request):
    """
    Handle user registration.
    """
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]

        # Ensure password matches confirmation
        password = request.POST["password"]
        confirmation = request.POST["confirmation"]
        if password != confirmation:
            return render(request, "auctions/register.html", {
                "message": "Passwords must match."
            })

        # Attempt to create new user
        try:
            user = User.objects.create_user(username, email, password)
            user.save()
        except IntegrityError:
            return render(request, "auctions/register.html", {
                "message": "Username already taken."
            })
        login(request, user)
        return HttpResponseRedirect(reverse("index"))
    else:
        return render(request, "auctions/register.html")

def convert_to_decimal(value):
    """
    Convert a given value to Decimal.
    """
    try:
        return Decimal(value)
    except (ValueError, TypeError, DecimalException):
        return None
    
@login_required
def create_listing(request):
    """
    Handle creation of a new auction listing.
    """
    categories = Category.objects.all()

    if request.method == 'POST':
        # Extract form data from the request
        title = request.POST.get('title')
        description = request.POST.get('description')

        # Convert starting_bid to Decimal
        starting_bid = convert_to_decimal(request.POST.get('starting_bid'))

        category_id = request.POST.get('category')
        images = request.FILES.getlist('images')

        if not title or not description or starting_bid is None or not category_id:
            return render(request, "auctions/create_listing.html", {
                "message": "Please fill out all required fields.",
                "categories": categories
            })

        try:
            # Get the Category object based on its ID
            category = Category.objects.get(id=category_id)

            # Create a new AuctionListing object
            listing = AuctionListing.objects.create(
                title=title,
                description=description,
                starting_bid=starting_bid,
                category=category,
                creator=request.user
            )

            # Save each image to Cloudinary
            uploaded_images = handle_image_uploads(listing, images)

        except IntegrityError:
            return render(request, "auctions/create_listing.html", {
                "message": "Title already taken.",
                "categories": categories
            })
        except Category.DoesNotExist:
            return render(request, "auctions/create_listing.html", {
                "message": "Selected category does not exist.",
                "categories": categories
            })

        return redirect('index')

    return render(request, 'auctions/create_listing.html', {'categories': categories})

@login_required
def place_bid(request, listing_id):
    """
    Handle placing a bid on an auction listing.
    """
    if request.method == 'POST':
        bid_amount = request.POST.get('bid')
        listing = get_object_or_404(AuctionListing, pk=listing_id)
        min_bid = listing.starting_bid if not listing.bids.exists() else listing.current_bid + Decimal('0.01')

        if not bid_amount:
            messages.error(request, 'Please enter a bid amount.')
            return redirect('listing_page', listing_id=listing_id)

        try:
            bid_amount = Decimal(bid_amount)
            if bid_amount >= min_bid:
                bid = Bid(listing=listing, bidder=request.user, amount=bid_amount)
                bid.save()
                listing.current_bid = bid_amount
                listing.current_bidder = request.user
                listing.save()
                messages.success(request, 'Bid placed successfully!')
            else:
                messages.error(request, f'Bid amount must be at least {min_bid}.')
        except (ValueError, InvalidOperation):
            messages.error(request, 'Please enter a valid bid amount.')

    return redirect('listing_page', listing_id=listing_id)

@login_required
def add_to_watchlist(request, listing_id):
    """
    Handle adding an auction listing to the user's watchlist.
    """
    if request.method == 'POST':
        listing = get_object_or_404(AuctionListing, pk=listing_id)
        if request.user.watchlist.filter(listing=listing).exists():
            # Listing is already in watchlist, remove it
            request.user.watchlist.filter(listing=listing).delete()
            messages.success(request, 'Listing removed from watchlist.')
        else:
            # Listing is not in watchlist, add it
            Watchlist.objects.create(user=request.user, listing=listing)
            messages.success(request, 'Listing added to watchlist.')
    return redirect('listing_page', listing_id=listing_id)

@login_required
def remove_from_watchlist(request, listing_id):
    """
    Handle removing an auction listing from the user's watchlist.
    """
    if request.method == 'POST':
        listing = get_object_or_404(AuctionListing, pk=listing_id)
        # Remove the listing from the user's watchlist if it exists
        request.user.watchlist.filter(listing=listing).delete()
        messages.success(request, 'Listing removed from watchlist.')
    return redirect('listing_page', listing_id=listing_id)

@login_required
def add_comment(request, listing_id):
    """
    Handle adding a comment to an auction listing.
    """
    listing = get_object_or_404(AuctionListing, pk=listing_id)
    if request.method == 'POST':
        comment_text = request.POST.get('content')
        if comment_text:
            comment = Comment(listing=listing, commenter=request.user, content=comment_text)
            comment.save()
            messages.success(request, 'Comment added successfully!')
        else:
            messages.error(request, 'Please enter a comment.')
    return redirect('listing_page', listing_id=listing_id)

@login_required
def close_auction(request, listing_id):
    """
    Handle closing an auction listing.
    """
    listing = get_object_or_404(AuctionListing, pk=listing_id)
    if request.method == 'POST':
        if request.user == listing.creator:
            listing.state = 'Closed'
            listing.save()
            messages.success(request, 'Auction closed successfully.')
        else:
            messages.error(request, 'You are not authorized to close this auction.')
    return redirect('listing_page', listing_id=listing_id)

def listing_page(request, listing_id):
    """
    Handle displaying an auction listing page.
    """
    listing = get_object_or_404(AuctionListing, pk=listing_id)
    has_won = listing.state == 'Closed' and listing.current_bidder == request.user
    in_watchlist = Watchlist.objects.filter(user=request.user, listing=listing).exists() if request.user.is_authenticated else False
    no_current_bid = listing.current_bid == 0  # Check if there is no current bid
    no_current_bidder = (listing.current_bidder is None)  # Check if there is no current bidder

    if request.method == 'POST':
        if 'place_bid' in request.POST:
            return place_bid(request, listing_id)
        elif 'watchlist' in request.POST:
            return add_to_watchlist(request, listing_id)
        elif 'remove_watchlist' in request.POST:  # Handle remove from watchlist action
            return remove_from_watchlist(request, listing_id)

    return render(request, 'auctions/listing_page.html', {
        'listing': listing,
        'has_won': has_won,
        'in_watchlist': in_watchlist,
        'no_current_bid': no_current_bid,
        'no_current_bidder': no_current_bidder,
    })

def handle_image_uploads(listing, images):
    """
    Handles uploading images to Cloudinary and associating them with a listing
    """
    uploaded_images = []
    for image in images:
        try:
            # Upload image to Cloudinary
            cloudinary_response = cloudinary.uploader.upload(image)
            image_url = cloudinary_response['url']
            
            # Create AuctionImage instance linking it to the listing
            auction_image = AuctionImage.objects.create(listing=listing, image=image_url)
            uploaded_images.append({
                'id': auction_image.id,
                'url': image_url,  # Assuming image_url is the Cloudinary URL
                'alt': listing.title
            })
        except Exception as e:
            # Handle upload failure gracefully
            print(f"Failed to upload image: {str(e)}")
    return uploaded_images

def delete_image_from_cloudinary(image):
    """
    Deletes an image from Cloudinary and its associated AuctionImage instance
    """
    try:
        # Extract public_id and timestamp for deletion signature
        public_id = image.image.public_id
        timestamp = int(time.time())
        params_to_sign = f'public_id={public_id}&timestamp={timestamp}'
        
        # Generate signature for deletion request
        signature = hmac.new(
            bytes(os.getenv('API_SECRET'), 'latin-1'),
            msg=params_to_sign.encode('utf-8'),
            digestmod=hashlib.sha1
        ).hexdigest()
        
        # Delete image from Cloudinary using generated signature
        cloudinary.uploader.destroy(public_id, api_key=os.getenv('API_KEY'), api_secret=os.getenv('API_SECRET'), signature=signature, timestamp=timestamp)
        
        # Delete AuctionImage instance from database
        image.delete()
    except Exception as e:
        # Handle deletion failure gracefully
        print(f"Failed to delete image: {str(e)}")

def update_listing_fields(listing, title, description, category_id):
    """
    Updates fields (title, description, category) of a listing instance
    """
    listing.title = title
    listing.description = description
    listing.category = Category.objects.get(id=category_id)
    listing.save()

def validate_form_fields(title, description, category_id):
    """
    Validates that required form fields (title, description, category_id) are not empty
    """
    return bool(title and description and category_id)

@login_required
@csrf_exempt
def edit_listing(request, listing_id):
    """
    Handles the submission of form data for updating a listing
    """
    listing = get_object_or_404(AuctionListing, id=listing_id)

    if request.method == 'POST':
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            # AJAX image upload request
            return handle_ajax_image_upload(request, listing)
        else:
            # Regular form submission
            return handle_form_submission(request, listing)

    elif request.method == 'DELETE':
        # Image deletion request
        return handle_image_deletion(request)

    # Fetches all categories for rendering the form
    categories = Category.objects.all()
    return render(request, 'auctions/edit_listing.html', {
        'listing': listing,
        'categories': categories
    })

def handle_form_submission(request, listing):
    """
    Handles form submission for updating a listing
    """
    title = request.POST.get('title')
    description = request.POST.get('description')
    category_id = request.POST.get('category')
    images = request.FILES.getlist('images')

    # Validate form fields
    if not validate_form_fields(title, description, category_id):
        categories = Category.objects.all()
        return render(request, 'auctions/edit_listing.html', {
            'listing': listing,
            'categories': categories,
            'message': 'Please fill out all required fields.'
        })

    try:
        # Update listing fields
        update_listing_fields(listing, title, description, category_id)

        # Handle image uploads if any
        if images:
            handle_image_uploads(listing, images)

        # Redirect to listing page on success
        messages.success(request, 'Your listing was successfully updated!')
        return redirect('listing_page', listing_id=listing.id)

    except IntegrityError:
        # Handle integrity errors (e.g., database constraints violated)
        messages.error(request, 'There was an error updating the listing.')
        categories = Category.objects.all()
        return render(request, 'auctions/edit_listing.html', {
            'listing': listing,
            'categories': categories,
            'message': 'There was an error updating the listing.'
        })

def handle_ajax_image_upload(request, listing):
    """
    Handles AJAX image uploads for a listing
    """
    images = request.FILES.getlist('images')
    new_images_data = handle_image_uploads(listing, images)
    return JsonResponse({'success': True, 'images': new_images_data})

def handle_image_deletion(request):
    """
    Handles deletion of an image associated with a listing
    """
    image_id = request.GET.get('image_id')
    try:
        # Retrieve and delete AuctionImage instance
        image = AuctionImage.objects.get(id=image_id)
        delete_image_from_cloudinary(image)
        return JsonResponse({'success': True})
    except AuctionImage.DoesNotExist:
        # Handle case where image does not exist
        return JsonResponse({'success': False, 'error': 'Image not found'}, status=404)

@login_required
def show_watchlist(request):
    """
    Show watchlist page
    """
    watchlist_listings = request.user.watchlist.all()
    
    # Print listings information to console
    for watchlist_item in watchlist_listings:
        listing = watchlist_item.listing
        print(f"Title: {listing.title}, Description: {listing.description}, Current Bid: {listing.current_bid}, Image URL: {listing.image_url}")

    return render(request, 'auctions/watchlist.html', {'watchlist_listings': watchlist_listings})

@login_required
def show_closed_auctions(request):
    """
    Show closed auctions page
    """
    closed_listings = AuctionListing.objects.filter(state='Closed')
    context = {
        'closed_listings': closed_listings
    }
    return render(request, 'auctions/closed_auctions.html', context)

@login_required
def update_profile(request):
    """
    Update user profile
    """
    user = request.user
    
    if request.method == 'POST':
        email = request.POST.get('email')
        first_name = request.POST.get('name')
        last_name = request.POST.get('lastname')
        user.email = email
        user.first_name = first_name
        user.last_name = last_name
        user.save()
        messages.success(request, 'Your profile was successfully updated!')
        return redirect('edit_profile')
    
    return render(request, 'auctions/edit_profile.html', {'user': user})

@login_required
def change_password(request):
    """
    Change user password
    """
    user = request.user
    
    if request.method == 'POST':
        password_form = PasswordChangeForm(user, request.POST)
        if password_form.is_valid():
            user = password_form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password was successfully updated!')
            return redirect('edit_profile')
    else:
        password_form = PasswordChangeForm(user)
    
    return render(request, 'auctions/edit_profile.html', {'user': user, 'password_form': password_form})

@login_required
def edit_profile(request):
    """
    Edit user profile
    """
    if request.method == 'POST':
        if 'save_profile' in request.POST:
            return update_profile(request)
        elif 'change_password' in request.POST:
            return change_password(request)
    
    user = request.user
    password_form = PasswordChangeForm(user)
    
    return render(request, 'auctions/edit_profile.html', {'user': user, 'password_form': password_form})

def user_profile(request, user_id):
    """
    User profile page
    """
    user = get_object_or_404(User, id=user_id)
    context = {
        'profile_user': user,
        'is_creator': False,
        'is_own_profile': request.user.id == user.id,
    }
    return render(request, 'auctions/profile.html', context)

def creator_profile(request, creator_id):
    """
    Creator profile page
    """
    creator = get_object_or_404(User, id=creator_id)
    context = {
        'profile_user': creator,
        'is_creator': True,
        'is_own_profile': request.user.id == creator.id,
    }
    return render(request, 'auctions/profile.html', context)
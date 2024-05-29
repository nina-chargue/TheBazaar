from django.contrib.auth.models import AbstractUser
from django.db import models
from commerce.settings import STATE_CHOICES


class User(AbstractUser):
    name = models.CharField(max_length=100, default='')
    lastname = models.CharField(max_length=100, default='')

# auction categories class?
class Category(models.Model):
    name = models.CharField(max_length=50)

    def __str__(self):
        return self.name

# auction listings class
class AuctionListing(models.Model):
    title = models.CharField(max_length=100)
    description = models.TextField()
    starting_bid = models.DecimalField(max_digits=10, decimal_places=2)
    current_bid = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    image_url = models.URLField(blank=True, null=True)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='listings', blank=True, null=True)
    date_created = models.DateTimeField(auto_now_add=True)
    creator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='listings')
    state = models.CharField(max_length=20, choices=STATE_CHOICES, default='Active')
    current_bidder = models.ForeignKey(User, on_delete=models.CASCADE, blank=True, null=True)

    def __str__(self):
        return self.title

# bids class
class Bid(models.Model):
    listing = models.ForeignKey(AuctionListing, on_delete=models.CASCADE, related_name='bids')
    bidder = models.ForeignKey(User, on_delete=models.CASCADE)
    amount = models.DecimalField(max_digits=10, decimal_places=2)
    timestamp = models.DateTimeField(auto_now_add=True)

# comments class
class Comment(models.Model):
    listing = models.ForeignKey(AuctionListing, on_delete=models.CASCADE, related_name='comments')
    commenter = models.ForeignKey(User, on_delete=models.CASCADE)
    content = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

class Watchlist(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='watchlist')
    listing = models.ForeignKey(AuctionListing, on_delete=models.CASCADE, related_name='watchers')

    def __str__(self):
        return f"{self.user.username}'s Watchlist"

# python manage.py makemigrations
# python manage.py migrate
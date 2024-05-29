from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    path("register/", views.register, name="register"),
    path("create_listing/", views.create_listing, name="create_listing"),
    path("listing_page/<str:listing_id>/", views.listing_page, name="listing_page"),
    path("place_bid/<int:listing_id>/", views.place_bid, name="place_bid"),
    path("add_to_watchlist/<int:listing_id>/", views.add_to_watchlist, name="add_to_watchlist"),
    path("remove_from_watchlist/<int:listing_id>/", views.remove_from_watchlist, name="remove_from_watchlist"),
    path("comment/<int:listing_id>/", views.add_comment, name="add_comment"),
    path("show_watchlist/", views.show_watchlist, name="show_watchlist"),
    path("close_auction/<int:listing_id>/", views.close_auction, name="close_auction"),
    path("edit_profile/", views.edit_profile, name="edit_profile"),
    path('user_profile/<int:user_id>/', views.user_profile, name='user_profile'),
    path('creator_profile/<int:creator_id>/', views.creator_profile, name='creator_profile'),
    path("show_closed_auctions/", views.show_closed_auctions, name="show_closed_auctions"),
    ]

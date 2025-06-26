import uuid

import os
from django.db import models


class Otp(models.Model):
    phone = models.CharField(max_length=10)
    otp = models.IntegerField()
    validity = models.DateTimeField()
    verified = models.BooleanField(default=False)

    def __str__(self):
        return self.phone


class Category(models.Model):
    name = models.CharField(max_length=50)
    position = models.IntegerField(default=0)
    image = models.ImageField(upload_to='categories/')

    def __str__(self):
        return self.name


class Slide(models.Model):
    position = models.IntegerField(default=0)
    image = models.ImageField(upload_to='categories/')


class Product(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='products_set')
    title = models.CharField(max_length=500)
    description = models.TextField(max_length=100000)
    price = models.IntegerField(default=0)
    offer_price = models.IntegerField(default=0)
    delivery_charge = models.IntegerField(default=0)
    star_5 = models.IntegerField(default=0)
    star_4 = models.IntegerField(default=0)
    star_3 = models.IntegerField(default=0)
    star_2 = models.IntegerField(default=0)
    star_1 = models.IntegerField(default=0)
    cod = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class ProductOption(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    product = models.ForeignKey(Product, on_delete=models.CASCADE, related_name='options_set')
    option = models.CharField(max_length=50, blank=True)
    quantity = models.IntegerField(default=0)

    def __str__(self):
        return f"({self.option}) {self.product.title}"


class User(models.Model):
    email = models.EmailField()
    phone = models.CharField(max_length=10)
    fullname = models.CharField(max_length=100)
    password = models.CharField(max_length=5000)
    wishlist = models.ManyToManyField(ProductOption, blank=True, related_name="wishlist")
    cart = models.ManyToManyField(ProductOption, blank=True, related_name="cart")
    created_at = models.DateTimeField(auto_now_add=True)
    # address fields
    name = models.CharField(max_length=100, blank=True)
    address = models.TextField(max_length=1000, blank=True)
    pincode = models.IntegerField(blank=True, null=True)
    contact_no = models.CharField(max_length=10, blank=True)
    district = models.CharField(max_length=500, blank=True)
    state = models.CharField(max_length=500, blank=True)

    def __str__(self):
        return self.email


class Token(models.Model):
    token = models.CharField(max_length=5000)
    fcmtoken = models.CharField(max_length=5000)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="tokens_set")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.user.email


class PasswordResetToken(models.Model):
    token = models.CharField(max_length=5000)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="password_reset_tokens_set")
    validity = models.DateTimeField()

    def __str__(self):
        return self.user.email


class ProductImage(models.Model):
    position = models.IntegerField(default=0)
    image = models.ImageField(upload_to='product/')
    product_option = models.ForeignKey(ProductOption, on_delete=models.CASCADE, related_name='images_set')


class PageItem(models.Model):
    position = models.IntegerField(default=0)
    image = models.ImageField(upload_to='product/', blank=True)
    category = models.ForeignKey(Category, on_delete=models.CASCADE, related_name='pageitems_set')
    choices = [
        (1, 'BANNER'),
        (2, 'SWIPER'),
        (3, 'GRID'),
    ]
    viewtype = models.IntegerField(choices=choices)
    title = models.CharField(max_length=50, blank=True)
    product_options = models.ManyToManyField(ProductOption, blank=True)

    def __str__(self):
        return self.category.name


class Order(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    seen = models.BooleanField(default=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="orders_set")
    tx_amount = models.IntegerField(default=0)
    payment_mode = models.CharField(max_length=100, null=True)
    address = models.TextField(max_length=5000)
    tx_id = models.CharField(max_length=1000, null=True)
    tx_choices = [
        ('INITIATED', 'INITIATED'),
        ('PENDING', 'PENDING'),
        ('INCOMPLETE', 'INCOMPLETE'),
        ('FAILED', 'FAILED'),
        ('FLAGGED', 'FLAGGED'),
        ('USER_DROPPED', 'USER_DROPPED'),
        ('SUCCESS', 'SUCCESS'),
        ('CANCELLED', 'CANCELLED'),
        ('VOID', 'VOID'),
    ]
    tx_status = models.CharField(choices=tx_choices, max_length=100, null=True)
    tx_time = models.CharField(max_length=500, null=True)
    tx_msg = models.CharField(max_length=500, null=True)

    from_cart = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    #todo temp.
    latitude = models.DecimalField(
        max_digits=9, decimal_places=6,
        null=True, blank=True,
        help_text="Customer location latitude"
    )
    longitude = models.DecimalField(
        max_digits=9, decimal_places=6,
        null=True, blank=True,
        help_text="Customer location longitude"
    )



class OrderedProduct(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    order = models.ForeignKey(Order, on_delete=models.CASCADE, related_name="orders_set")
    product_option = models.ForeignKey(ProductOption, on_delete=models.CASCADE, related_name="order_options_set")
    product_price = models.IntegerField(default=0)
    tx_price = models.IntegerField(default=0)
    delivery_price = models.IntegerField(default=0)
    quantity = models.IntegerField(default=1)
    choices = [
        ('ORDERED', 'ORDERED'),
        ('OUT_FOR_DELIVERY', 'OUT_FOR_DELIVERY'),
        ('DELIVERED', 'DELIVERED'),
        ('CANCELLED', 'CANCELLED'),
    ]
    rating = models.IntegerField(default=0)
    status = models.CharField(choices=choices, default='ORDERED', max_length=100)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)


class Notification(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="notifications_set")
    title = models.CharField(max_length=225)
    body = models.TextField(max_length=1000)
    seen = models.BooleanField(default=False)
    image = models.ImageField(upload_to="notifications/", blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

class ContactInfo(models.Model):
    phone_number = models.CharField(max_length=15)

    def __str__(self):
        return self.phone_number


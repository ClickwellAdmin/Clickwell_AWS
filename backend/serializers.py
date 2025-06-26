from rest_framework.fields import SerializerMethodField
from rest_framework.serializers import ModelSerializer
from rest_framework import serializers

from backend.models import User, Category, Slide, Product, ProductOption, ProductImage, PageItem, OrderedProduct, \
    Notification , ContactInfo


class UserSerializer(ModelSerializer):
    notifications = SerializerMethodField()
    class Meta:
        model = User
        fields = ['email','notifications', 'phone', 'fullname', 'wishlist', 'cart', 'name', 'address', 'contact_no', 'pincode', 'state',
                  'district']

    def get_notifications(self,obj):
        list = obj.notifications_set.filter(seen=False)
        return len(list)


class AddressSerializer(ModelSerializer):
    class Meta:
        model = User
        fields = ['name', 'address', 'contact_no', 'pincode', 'state', 'district']


class CategorySerializer(ModelSerializer):
    image = serializers.SerializerMethodField()

    class Meta:
        model = Category
        fields = ['id', 'name', 'position', 'image']

    def get_image(self, obj):
        request = self.context.get('request')
        if obj.image:
            image_url = obj.image.url
            return request.build_absolute_uri(image_url) if request else image_url
        return None


class SlideSerializer(ModelSerializer):
    class Meta:
        model = Slide
        fields = ['position', 'image']


# Enhanced ProductSerializer with better image handling
class ProductSerializer(ModelSerializer):
    options = SerializerMethodField()
    category_name = SerializerMethodField()

    class Meta:
        model = Product
        fields = ['id', 'title', 'description', 'price', 'offer_price', 'delivery_charge', 'cod', 'star_5', 'star_4',
                  'star_3', 'star_2', 'star_1', 'options', 'category_name', 'created_at', 'updated_at']

    def get_options(self, obj):
        options = obj.options_set.all()
        data = ProductOptionSerializer(options, many=True, context=self.context).data
        return data

    def get_category_name(self, obj):
        return obj.category.name if obj.category else None




class ProductOptionSerializer(ModelSerializer):
    images = SerializerMethodField()

    class Meta:
        model = ProductOption
        fields = ['id', 'option', 'quantity', 'images']

    def get_images(self, obj):
        images = obj.images_set.all()
        data = ProductImageSerializer(images, many=True).data
        return data




class ProductImageSerializer(ModelSerializer):
    class Meta:
        model = ProductImage
        fields = ['position', 'image', 'product_option']


class WishlistSerializer(ModelSerializer):
    id = SerializerMethodField()
    title = SerializerMethodField()
    price = SerializerMethodField()
    offer_price = SerializerMethodField()
    image = SerializerMethodField()

    def get_id(self, obj):
        return obj.product.id

    def get_title(self, obj):
        return obj.__str__()

    def get_price(self, obj):
        return obj.product.price

    def get_offer_price(self, obj):
        return obj.product.offer_price

    def get_image(self, obj):
        return ProductImageSerializer(obj.images_set.order_by('position').first(), many=False).data.get(
            'image')

    class Meta:
        model = ProductOption
        fields = ['id', 'title', 'image', 'price', 'offer_price']


class CartSerializer(WishlistSerializer):
    cod = SerializerMethodField()
    delivery_charge = SerializerMethodField()
    id = SerializerMethodField()

    def get_cod(self, obj):
        return obj.product.cod

    def get_delivery_charge(self, obj):
        return obj.product.delivery_charge

    def get_id(self, obj):
        return obj.id

    class Meta:
        model = ProductOption
        fields = ['id', 'title', 'image', 'price', 'offer_price', 'quantity', 'cod', 'delivery_charge']


class PageItemSerializer(ModelSerializer):
    product_options = SerializerMethodField()

    class Meta:
        model = PageItem
        fields = ['id', 'position', 'image', 'category', 'title', 'viewtype', 'product_options']

    def get_product_options(self, obj):
        options = obj.product_options.all()[:8]
        data = []
        for option in options:
            data.append({
                'id': option.product.id,
                'image': ProductImageSerializer(option.images_set.order_by('position').first(), many=False).data.get(
                    'image'),
                'title': option.__str__(),
                'price': option.product.price,
                'offer_price': option.product.offer_price,
            })

        return data


class OrderItemSerializer(ModelSerializer):
    title = SerializerMethodField()
    image = SerializerMethodField()
    created_at = SerializerMethodField()

    class Meta:
        model = OrderedProduct
        fields = ['id', 'title', 'image', 'created_at', 'quantity', 'status', 'rating']

    def get_title(self, obj):
        return obj.product_option.__str__()

    def get_image(self, obj):
        return ProductImageSerializer(obj.product_option.images_set.order_by('position').first(), many=False).data.get(
            'image')

    def get_created_at(self, obj):
        return obj.created_at.strftime("%d %b %Y %H:%M %p")


class OrderDetailsSerializer(OrderItemSerializer):
    payment_mode = SerializerMethodField()
    address = SerializerMethodField()
    tx_id = SerializerMethodField()
    tx_status = SerializerMethodField()
    user_phone = SerializerMethodField()

    #temp. code
    latitude = serializers.DecimalField(
        max_digits=9, decimal_places=6,
        required=False, allow_null=True
    )
    longitude = serializers.DecimalField(
        max_digits=9, decimal_places=6,
        required=False, allow_null=True
    )

    class Meta:
        model = OrderedProduct
        fields = ['id', 'title', 'image', 'created_at', 'quantity', 'status', 'rating'
                  ,'product_price','tx_price','delivery_price','payment_mode','address','tx_id','tx_status','latitude','longitude','user_phone']

    def get_payment_mode(self,obj):
        return obj.order.payment_mode

    def get_address(self,obj):
        return obj.order.address

    def get_tx_id(self,obj):
        return obj.order.tx_id

    def get_tx_status(self,obj):
        return obj.order.tx_status

    def get_user_phone(self, obj):
        return obj.order.user.phone


class NotificationSerializer(ModelSerializer):
    created_at = SerializerMethodField()
    class Meta:
        model = Notification
        fields = ['id','title','body','image','seen','created_at']


    def get_created_at(self, obj):
        return obj.created_at.strftime("%d %b %Y %H:%M %p")

class PrivacyPolicySerializer(serializers.Serializer):
    content = serializers.CharField(trim_whitespace=False)

class ContactUsSerializer(serializers.Serializer):
    content = serializers.CharField(trim_whitespace=False)


# class OrderDetailSerializer(serializers.ModelSerializer):
#     user = serializers.CharField(source='user.email', read_only=True)  # Fetch email from user

#     class Meta:
#         model = Order
#         fields = [
#             'id', 'user', 'tx_amount', 'payment_mode', 'address', 'tx_id',
#             'tx_status', 'tx_time', 'tx_msg', 'from_cart', 'created_at', 'updated_at'
#         ]




class ItemOrderSerializer(serializers.ModelSerializer):
    product_option = serializers.CharField(source='product_option.option')  # Option name
    product_title = serializers.CharField(source='product_option.product.title')  # Product title
    product_image = serializers.SerializerMethodField()  # Absolute product image URL
    user_fullname = serializers.CharField(source='order.user.fullname', read_only=True)  # User full name
    user_phone = serializers.CharField(source='order.user.phone', read_only=True)  # User phone number
    payment_mode = serializers.CharField(source='order.payment_mode', read_only=True)  # Payment mode
    tx_status = serializers.CharField(source='order.tx_status', read_only=True)  # Transaction status
    tx_msg = serializers.CharField(source='order.tx_msg', read_only=True)  # Transaction message
    address = serializers.CharField(source='order.address', read_only=True)  # Order address
    related_products = serializers.SerializerMethodField()  # Add related products


    class Meta:
        model = OrderedProduct
        fields = [
            'id',
            'quantity',
            'product_option',
            'product_title',
            'product_image',
            'user_fullname',
            'user_phone',
            'payment_mode',
            'tx_status',
            'tx_msg',
            'address',
            'tx_price',
            'product_price',
            'delivery_price',
            'status',
            'created_at',
            'updated_at',
            'related_products',
        ]

    def get_product_image(self, obj):
        if obj.product_option.images_set.exists():
            request = self.context.get('request')  # Access the request object
            image_url = obj.product_option.images_set.first().image.url
            return request.build_absolute_uri(image_url) if request else f"/{image_url.lstrip('/')}"
        return None

    def get_related_products(self, obj):
        # Get all products from the same order, excluding the current one
        related_products = OrderedProduct.objects.filter(
            order=obj.order
        ).exclude(
            id=obj.id
        )

        # Return serialized data for related products
        return RelatedProductSerializer(related_products, many=True, context=self.context).data

class ContactInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = ContactInfo
        fields = ['phone_number']


class RelatedProductSerializer(serializers.ModelSerializer):
    product_option = serializers.CharField(source='product_option.option')
    product_title = serializers.CharField(source='product_option.product.title')
    product_image = serializers.SerializerMethodField()

    class Meta:
        model = OrderedProduct
        fields = [
            'id',
            'product_option',
            'product_title',
            'product_image',
            'quantity',
            'product_price',
            'tx_price',
            'status',
        ]

    def get_product_image(self, obj):
        if obj.product_option.images_set.exists():
            request = self.context.get('request')
            image_url = obj.product_option.images_set.first().image.url
            return request.build_absolute_uri(image_url) if request else f"/{image_url.lstrip('/')}"
        return None


# Validation serializers for API requests
class ProductCreateSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=500)
    description = serializers.CharField(max_length=100000, allow_blank=True)
    price = serializers.IntegerField(min_value=0)
    offer_price = serializers.IntegerField(min_value=0)
    delivery_charge = serializers.IntegerField(min_value=0, default=0)
    cod = serializers.BooleanField(default=False)
    category = serializers.CharField()

    def validate_category(self, value):
        try:
            category = Category.objects.get(id=value)
            return category
        except Category.DoesNotExist:
            raise serializers.ValidationError("Category not found")

    def validate(self, data):
        if data['offer_price'] > data['price']:
            raise serializers.ValidationError("Offer price cannot be greater than original price")
        return data


class ProductOptionCreateSerializer(serializers.Serializer):
    product = serializers.CharField()
    option = serializers.CharField(max_length=50)
    quantity = serializers.IntegerField(min_value=0, default=0)

    def validate_product(self, value):
        try:
            product = Product.objects.get(id=value)
            return product
        except Product.DoesNotExist:
            raise serializers.ValidationError("Product not found")


class ProductUpdateSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=500, required=False)
    description = serializers.CharField(max_length=100000, allow_blank=True, required=False)
    price = serializers.IntegerField(min_value=0, required=False)
    offer_price = serializers.IntegerField(min_value=0, required=False)
    delivery_charge = serializers.IntegerField(min_value=0, required=False)
    cod = serializers.BooleanField(required=False)

    def validate(self, data):
        # If both price and offer_price are provided, validate them
        if 'price' in data and 'offer_price' in data:
            if data['offer_price'] > data['price']:
                raise serializers.ValidationError("Offer price cannot be greater than original price")
        return data


class ProductOptionUpdateSerializer(serializers.Serializer):
    option = serializers.CharField(max_length=50, required=False)
    quantity = serializers.IntegerField(min_value=0, required=False)


class BulkStockUpdateSerializer(serializers.Serializer):
    option_id = serializers.CharField()
    quantity = serializers.IntegerField(min_value=0)

    def validate_option_id(self, value):
        try:
            option = ProductOption.objects.get(id=value)
            return option
        except ProductOption.DoesNotExist:
            raise serializers.ValidationError("Product option not found")


class ImageUploadSerializer(serializers.Serializer):
    product_option = serializers.CharField()
    position = serializers.IntegerField(min_value=0, default=0)
    image = serializers.ImageField()

    def validate_product_option(self, value):
        try:
            option = ProductOption.objects.get(id=value)
            return option
        except ProductOption.DoesNotExist:
            raise serializers.ValidationError("Product option not found")

    def validate_image(self, value):
        # Validate file size (5MB max)
        if value.size > 5 * 1024 * 1024:
            raise serializers.ValidationError("Image file too large (max 5MB)")


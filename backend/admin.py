from django.contrib import admin
from django.contrib.admin import register
from django.contrib.auth.models import Group, User as AUser

from backend.models import User, Otp, Token, PasswordResetToken, Category, Slide, Product, ProductOption, ProductImage, \
    PageItem, Order, OrderedProduct, Notification  , ContactInfo
from backend.utils import send_user_notification

from .models import User
from .decorators import password_protected_view

admin.site.unregister(Group)
admin.site.unregister(AUser)

admin.site.site_header = "ClickWell Admin"
admin.site.site_title = "ClickWell Admin"
admin.site.index_title = "Welcome to ClickWell Admin Panel"


@register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ['id', 'email', 'phone', 'fullname', 'address', 'pincode', 'created_at']
    fieldsets = (
        ('User info', {
            'fields': ('email', 'phone', 'fullname', 'password',)
        }),
        ('Address info', {
            'fields': ('name', 'address', 'contact_no', 'pincode', 'district', 'state',)
        }),
    )
    readonly_fields = ['password', 'email','phone','fullname','name','address','pincode','district', 'state','contact_no']
    search_fields = ['id','email','phone','fullname','address','pincode']
    search_help_text =  "Search by id,email,phone,fullname,address,pincode"

    @password_protected_view('userAdmin@1612') #password for userAdmin
    def changelist_view(self, request, extra_context=None):
        return super().changelist_view(request, extra_context)

    @password_protected_view('userAdmin@1612') ##password for userAdmin
    def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
        return super().changeform_view(request, object_id, form_url, extra_context)


@register(Otp)
class OtpAdmin(admin.ModelAdmin):
    list_display = ['phone', 'otp', 'validity', 'verified']

    def has_add_permission(self, request):
        return False

  #  @password_protected_view('otp_admin@1612') #password for OtpAdmin
   # def changelist_view(self, request, extra_context=None):
    #    return super().changelist_view(request, extra_context)

   # @password_protected_view('otp_admin@1612') #password for OtpAdmin
    #def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
     #   return super().changeform_view(request, object_id, form_url, extra_context)

@register(Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = ['token', 'fcmtoken', 'user', 'created_at']

    def has_add_permission(self, request):
        return False


@register(PasswordResetToken)
class PasswordResetTokenAdmin(admin.ModelAdmin):
    list_display = ['token', 'user', 'validity']

    def has_add_permission(self, request):
        return False


@register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'position', 'image']

    @password_protected_view('hesoyam@24') #password for CategoryAdmin
    def changelist_view(self, request, extra_context=None):
        return super().changelist_view(request, extra_context)

    @password_protected_view('hesoyam@24') #password for CategoryAdmin
    def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
        return super().changeform_view(request, object_id, form_url, extra_context)


@register(Slide)
class SlideAdmin(admin.ModelAdmin):
    list_display = ['position', 'image']

    @password_protected_view('promotion_admin@24') #password for SlideAdmin
    def changelist_view(self, request, extra_context=None):
        return super().changelist_view(request, extra_context)

    @password_protected_view('promotion_admin@24') #password for SlideAdmin
    def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
        return super().changeform_view(request, object_id, form_url, extra_context)




class ProductOptionInline(admin.TabularInline):
    list = ['id', 'product', 'option', 'quantity']
    model = ProductOption
    extra = 0
    show_change_link = True



@register(Product)
class ProductAdmin(admin.ModelAdmin):
    inlines = [ProductOptionInline]
    list_display = ['id', 'category', 'title', 'price', 'offer_price', 'delivery_charge', 'cod', 'created_at',
                    'updated_at']
    readonly_fields = ['star_1','star_2','star_3','star_4','star_5']
    list_filter = ['cod','category']
    search_fields = ['id','title',]
    search_help_text = "Search by Id, title"


class ProductImageInline(admin.TabularInline):
    list = ['image', 'position']
    model = ProductImage
    extra = 0
    min_num = 1


@register(ProductOption)
class ProductOptionAdmin(admin.ModelAdmin):
    inlines = [ProductImageInline]
    list_display = ['id', 'product', 'option', 'quantity']
    search_fields = ['product__title','option','quantity']
    search_help_text = 'Search by, Product, Option, Quantity'


@register(PageItem)
class PageItemAdmin(admin.ModelAdmin):
    list_display = ['id', 'title', 'position', 'image', 'category', 'viewtype']
    filter_horizontal = ['product_options']
    list_filter = ['viewtype','category']
    search_fields = ['title']
    search_help_text = "Search by title"

    @password_protected_view('pageitem@24') #password for pageitem
    def changelist_view(self, request, extra_context=None):
        return super().changelist_view(request, extra_context)

    @password_protected_view('pageitem@24') ##password for pageitem
    def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
        return super().changeform_view(request, object_id, form_url, extra_context)


@register(OrderedProduct)
class OrderedProductAdmin(admin.ModelAdmin):
    list_display = ['id', 'order', 'product_option', 'product_price', 'tx_price', 'delivery_price', 'quantity',
                    'status', 'rating', 'created_at', 'updated_at']
    readonly_fields = ['order','product_option', 'product_price', 'tx_price', 'delivery_price', 'quantity', 'rating']
    search_fields = ['id']
    search_help_text = "Search by Id"
    list_filter = ['status']
    ordering = ['-created_at']

    def save_model(self, request, ordered_product, form, change):
        super(OrderedProductAdmin, self).save_model( request, ordered_product, form, change)
        user = ordered_product.order.user
        title = "ORDER "+ordered_product.status
        body = "Your "+ordered_product.product_option.__str__()+" has been "+ordered_product.status+"."
        image = ordered_product.product_option.images_set.first().image
        print("ORDER STATUS: "+title)
        send_user_notification(user,title,body,image)

    def has_add_permission(self, request):
        return False



class OrderedProductInline(admin.TabularInline):
    model = OrderedProduct
    list = ['id', 'product_option', 'product_price', 'tx_price', 'delivery_price', 'quantity', 'status']
    readonly_fields = ['product_option', 'product_price', 'tx_price', 'delivery_price', 'quantity', 'status', 'rating']

    show_change_link = True

    extra = 0

    def has_add_permission(self, request, obj):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@register(Order)
class OrderAdmin(admin.ModelAdmin):
    inlines = [OrderedProductInline]
    list_display = ['id','seen', 'user', 'tx_amount', 'payment_mode', 'address', 'tx_id', 'tx_status', 'tx_time', 'tx_msg',
                    'from_cart', 'created_at', 'updated_at']
    list_filter = ['payment_mode', 'tx_status', 'from_cart']
    ordering = ['-created_at']
    readonly_fields = ['user', 'tx_amount', 'payment_mode', 'tx_id', 'tx_time', 'tx_msg', 'from_cart']
    search_fields = ['id','user__email','address','tx_id', ]
    search_help_text = "Search by Id, user, address, tx_id"

    def has_add_permission(self, request):
        return False


@register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['id', 'title', 'body', 'image', 'seen', 'created_at']

    @password_protected_view('notificationadmin') #password for pageitem
    def changelist_view(self, request, extra_context=None):
        return super().changelist_view(request, extra_context)

    @password_protected_view('notificationadmin') ##password for pageitem
    def changeform_view(self, request, object_id=None, form_url='', extra_context=None):
        return super().changeform_view(request, object_id, form_url, extra_context)

@admin.register(ContactInfo)
class ContactInfoAdmin(admin.ModelAdmin):
    list_display = ['id', 'phone_number']
    fields = ['phone_number']
    search_fields = ['phone_number']
    search_help_text = "Search by phone number"

    def has_add_permission(self, request):
        # Allow only one ContactInfo entry
        if ContactInfo.objects.exists():
            return False
        return super().has_add_permission(request)



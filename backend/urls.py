# urls.py - Enhanced URL patterns with bulk update endpoints
from django.urls import path

from backend.views import (
    # ... existing imports ...
    request_otp, verify_otp, create_account, login, password_reset_email, password_reset_form,
    password_reset_confirm, userdata, resend_otp, categories, slides, pageitems, product_details,
    update_wishlist, update_cart, wishlist, cart, updateaddress, notify_url, initiate_payment, orders, orderdetails,
    updaterating, search, updateinfo, update_phone_request_otp, change_password, logout, viewall, notifications,
    forgot_password, privacy_policy, PrivacyPolicyAPIView, forgotpassword, ContactUsAPIView, contact_us,
    verify_pass_otp, ChangePasswordView, newpassword, ordered_product_list, update_order_status,
    initiate_order, delete_account, fast2sms_verification,  get_phone_number, all_products,
    create_product, update_product_option, upload_product_image, delete_product_image, delete_product, update_product,
    get_product_details, get_categories, create_product_enhanced, update_product_enhanced, bulk_update_stock,
    delete_product_image_enhanced, upload_product_image_enhanced, update_product_option_enhanced, create_product_option,


)

urlpatterns = [
    # Authentication endpoints
    path('request_otp/', request_otp),
    path('resend_otp/', resend_otp),
    path('verify_otp/', verify_otp),
    path('create_account/', create_account),
    path('login/', login),
    path('logout/', logout),
    path('password_reset_email/', password_reset_email),
    path('password_reset_form/<email>/<token>/', password_reset_form, name="password_reset_form"),
    path('password_reset_confirm/', password_reset_confirm, name="password_reset_confirm"),
    path('userdata/', userdata),

    # Category and content endpoints
    path('categories/', categories),
    path('get_categories/', get_categories, name='get_categories'),
    path('slides/', slides),
    path('pageitems/', pageitems),
    path('productdetails/', product_details),
    path('viewall/', viewall),
    path('search/', search),

    # User management endpoints
    path('updatewishlist/', update_wishlist),
    path('updatecart/', update_cart),
    path('wishlist/', wishlist),
    path('cart/', cart),
    path('updateaddress/', updateaddress),
    path('updateinfo/', updateinfo),
    path('updatephone_otp/', update_phone_request_otp),
    path('changepassword/', change_password),
    path('deleteaccount/', delete_account, name='delete_account'),

    # Payment and order endpoints
    path('initiate_payment/', initiate_payment),
    path('notify_url/', notify_url),
    path('initiate_order/', initiate_order, name='initiate_order'),
    path('orders/', orders),
    path('orderdetails/', orderdetails),
    path('updaterating/', updaterating),

    # ORDER MANAGEMENT ENDPOINTS - Enhanced
    path('orderedProduct/', ordered_product_list, name='ordered_product_list'),

    # Single order status update (both old and enhanced versions)
    path('update_order_status/', update_order_status, name='update_order_status'),



    # Notification endpoints
    path('notifications/', notifications),

    # Password reset endpoints
    path('forgot_password/', forgot_password),
    path('forgot-password/', forgotpassword, name='forgot-password'),
    path('verify_pass_otp/', verify_pass_otp, name='verify_pass_otp'),
    path('change_password_otp/', ChangePasswordView.as_view(), name='change_password_otp'),
    path('newpassword/', newpassword, name="newpassword"),

    # Static pages
    path('privacy-policy/', privacy_policy, name='privacy_policy'),
    path('api/privacy-policy/', PrivacyPolicyAPIView.as_view(), name='privacy_policy_api'),
    path('contact_us/', contact_us, name='contact_us'),
    path('api/contact-us/', ContactUsAPIView.as_view(), name='contact_us_api'),

    # Utility endpoints
    path("fast2sms-verification/", fast2sms_verification, name="fast2sms_verification"),
    path('phone-number/', get_phone_number),

    # Product management endpoints
    path('all_products/', all_products, name='all_products'),
    path('products/<uuid:product_id>/', get_product_details, name='get_product_details'),
    path('products/<uuid:product_id>/update/', update_product, name='update_product'),
    path('products/<uuid:product_id>/delete/', delete_product, name='delete_product'),
    path('products/create/', create_product, name='create_product'),

    # Product option endpoints
    path('product-options/create/', create_product_option, name='create_product_option'),
    path('product-options/<uuid:option_id>/update/', update_product_option, name='update_product_option'),
    path('product-options/<uuid:option_id>/update/', update_product_option_enhanced,
         name='update_product_option_enhanced'),

    # Image management endpoints
    path('product-images/upload/', upload_product_image, name='upload_product_image'),
    path('product-images/<str:image_id>/delete/', delete_product_image, name='delete_product_image'),
    path('product-images/upload/', upload_product_image_enhanced, name='upload_product_image_enhanced'),
    path('product-images/<str:image_id>/delete/', delete_product_image_enhanced, name='delete_product_image_enhanced'),

    # Enhanced product endpoints
    path('products/create/', create_product_enhanced, name='create_product_enhanced'),
    path('products/<uuid:product_id>/update/', update_product_enhanced, name='update_product_enhanced'),

    # Bulk operations
    path('bulk-update-stock/', bulk_update_stock, name='bulk_update_stock'),
]


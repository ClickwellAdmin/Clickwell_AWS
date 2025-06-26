import os
import django
import pandas as pd
from datetime import datetime

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'core.settings')
django.setup()

# Import your models
from backend.models import Product, ProductOption, Category


def export_to_excel():
    # Get all products with options
    products = Product.objects.select_related('category').prefetch_related('options_set').all()

    data = []
    for product in products:
        options = product.options_set.all()

        if options:
            for option in options:
                data.append({
                    'Product Names': product.title,
                    'Options': option.option,
                    'Price': product.price,
                    'Offer Price': product.offer_price
                })
        else:
            data.append({
                'Product Names': product.title,
                'Options': 'No Options',
                'Price': product.price,
                'Offer Price': product.offer_price
            })

    # Create DataFrame and export
    df = pd.DataFrame(data)
    filename = f'products_with_options_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    df.to_excel(filename, index=False)

    print(f"Exported {len(data)} records to {filename}")


if __name__ == "__main__":
    export_to_excel()
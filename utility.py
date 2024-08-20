from bson import ObjectId

def serialize_document(doc):
    """ Convert MongoDB document to serializable format """
    if isinstance(doc, dict):
        for key, value in doc.items():
            if isinstance(value, ObjectId):
                doc[key] = str(value)
            elif isinstance(value, dict):
                doc[key] = serialize_document(value)
            elif isinstance(value, list):
                doc[key] = [serialize_document(item) for item in value]
    return doc
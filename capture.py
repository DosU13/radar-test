import os

import cv2


video_path = 'rtsp://admin:admin123@172.17.83.60:554/live'
video_capture = cv2.VideoCapture(video_path)
cv2.namedWindow('street_name', cv2.WINDOW_NORMAL)

while video_capture.isOpened():

    all_violators = {}
    success, raw_frame = video_capture.read()
    if not success:
        print("End of video or cannot read the frame.")
        break
    cv2.imshow('test', raw_frame)
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break
video_capture.release()
cv2.destroyAllWindows()

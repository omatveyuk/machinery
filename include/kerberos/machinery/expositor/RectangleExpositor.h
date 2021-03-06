//
//	Class: RectangleExpositor
//	Description: Calculate a bounding rectangle that contains 
//               all the changed pixels with a rectangle.
//  Created:     17/07/2014
//  Author:      Cédric Verstraeten
//  Mail:        hello@cedric.ws
//  Website:     www.kerberos.io
//
//  The copyright to the computer program(s) herein
//  is the property of kerberos.io, Belgium.
//  The program(s) may be used and/or copied .
//
/////////////////////////////////////////////////////

#ifndef __RectangleExpositor_H_INCLUDED__   // if RectangleExpositor.h hasn't been included yet...
#define __RectangleExpositor_H_INCLUDED__   // #define this so the compiler knows it has been included

#include "machinery/expositor/Expositor.h"

namespace kerberos
{
    char RectName[] = "Rectangle";
    class RectangleExpositor : public ExpositorCreator<RectName, RectangleExpositor>
    {
        public:
            RectangleExpositor(){};
            RectangleExpositor(int x1, int y1, int x2, int y2):m_x1(x1),m_y1(y1),m_x2(x2),m_y2(y2){};
            void setup(const StringMap & settings);
            void setCoordinates(const int x1, const int y1, const int x2, const int y2);
            void calculate(Image & image, JSON & data);
        
            int m_x1, m_x2;
            int m_y1, m_y2;
    };
}
#endif